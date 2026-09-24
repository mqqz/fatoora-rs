//! Immutable view of the original XML, without an invoice model round trip.
use super::{FailureKind, Limits};
use libxml::{
    parser::{Parser, ParserOptions},
    tree::{Node, NodeType},
};
use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};
use std::collections::{HashMap, HashSet};

pub(super) const UBL: &str = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2";
pub(super) const CREDIT_NOTE: &str = "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2";
pub(super) const CAC: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";
pub(super) const CBC: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";
pub(super) type NodeId = usize;
pub(super) type Name = (&'static str, &'static str);
pub(super) const fn a(name: &'static str) -> Name {
    (CAC, name)
}
pub(super) const fn b(name: &'static str) -> Name {
    (CBC, name)
}

#[derive(Debug)]
pub(super) struct Element {
    pub namespace: String,
    pub name: String,
    pub text: String,
    /// XDM child::text() values, excluding descendant element text.
    pub direct_text: Vec<String>,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub location: String,
    attributes: HashMap<(String, String), String>,
}

#[derive(Debug)]
pub(super) struct XmlView {
    nodes: Vec<Element>,
}

impl XmlView {
    pub fn parse(input: &str, limits: &Limits) -> Result<Self, FailureKind> {
        preflight(input, limits)?;
        let document = Parser::default()
            .parse_string_with_options(
                input,
                ParserOptions {
                    recover: false,
                    no_net: true,
                    huge: false,
                    // Preflight accepts only UTF-8 declarations. Keep encoding
                    // unset: libxml 0.3.8 drops the CString backing an override
                    // before passing its pointer to xmlReadMemory.
                    ..ParserOptions::default()
                },
            )
            .map_err(|e| FailureKind::InvalidXml(e.to_string()))?;
        let root = document
            .get_root_element()
            .ok_or_else(|| FailureKind::InvalidXml("missing root".into()))?;
        let mut view = Self { nodes: Vec::new() };
        view.copy_element(root, None, "", 1, &mut 0, limits)?;
        Ok(view)
    }

    fn copy_element(
        &mut self,
        node: Node,
        parent: Option<NodeId>,
        prefix: &str,
        ordinal: usize,
        retained: &mut usize,
        limits: &Limits,
    ) -> Result<NodeId, FailureKind> {
        let name = node.get_name();
        let namespace = node
            .get_namespace()
            .map_or_else(String::new, |ns| ns.get_href());
        let location = format!(
            "{prefix}/*[local-name()={} and namespace-uri()={}][{ordinal}]",
            xpath_literal(&name),
            xpath_literal(&namespace)
        );
        let text = node.get_content();
        // XML CDATA boundaries do not create XDM text-node boundaries. Other
        // child node kinds do, and zero-length text nodes are omitted.
        let mut direct_text = Vec::new();
        let mut text_run = String::new();
        for child in node.get_child_nodes() {
            if matches!(
                child.get_type(),
                Some(NodeType::TextNode | NodeType::CDataSectionNode)
            ) {
                text_run.push_str(&child.get_content());
            } else if !text_run.is_empty() {
                direct_text.push(std::mem::take(&mut text_run));
            }
        }
        if !text_run.is_empty() {
            direct_text.push(text_run);
        }
        let attributes: HashMap<_, _> = node
            .get_properties_ns()
            .into_iter()
            .map(|((name, ns), value)| {
                (
                    (ns.map_or_else(String::new, |ns| ns.get_href()), name),
                    value,
                )
            })
            .collect();
        let size = name.len()
            + namespace.len()
            + location.len()
            + text.len()
            + direct_text.iter().map(String::len).sum::<usize>()
            + attributes
                .iter()
                .map(|((ns, name), value)| ns.len() + name.len() + value.len())
                .sum::<usize>();
        *retained = retained
            .checked_add(size)
            .ok_or(FailureKind::Limit("XML retained bytes"))?;
        if *retained > limits.retained_bytes {
            return Err(FailureKind::Limit("XML retained bytes"));
        }
        let id = self.nodes.len();
        self.nodes.push(Element {
            namespace,
            name,
            text,
            direct_text,
            parent,
            children: Vec::new(),
            location: location.clone(),
            attributes,
        });
        let mut counts = HashMap::new();
        for child in node.get_child_elements() {
            let key = (
                child
                    .get_namespace()
                    .map_or_else(String::new, |ns| ns.get_href()),
                child.get_name(),
            );
            let ordinal = counts.entry(key).or_insert(0);
            *ordinal += 1;
            let child =
                self.copy_element(child, Some(id), &location, *ordinal, retained, limits)?;
            self.nodes[id].children.push(child);
        }
        Ok(id)
    }

    pub fn node(&self, id: NodeId) -> &Element {
        &self.nodes[id]
    }
    pub fn elements(&self) -> impl Iterator<Item = (NodeId, &Element)> {
        self.nodes.iter().enumerate()
    }
    pub fn all(&self, namespace: &str, name: &str) -> Vec<NodeId> {
        (0..self.nodes.len())
            .filter(|&id| self.is(id, namespace, name))
            .collect()
    }
    pub fn is(&self, id: NodeId, namespace: &str, name: &str) -> bool {
        self.node(id).namespace == namespace && self.node(id).name == name
    }
    pub fn is_document_root(&self, id: NodeId) -> bool {
        id == 0 && (self.is(id, UBL, "Invoice") || self.is(id, CREDIT_NOTE, "CreditNote"))
    }
    pub fn children(&self, id: NodeId, namespace: &str, name: &str) -> Vec<NodeId> {
        self.node(id)
            .children
            .iter()
            .copied()
            .filter(|&id| self.is(id, namespace, name))
            .collect()
    }
    pub fn path(&self, id: NodeId, steps: &[Name]) -> Vec<NodeId> {
        let mut nodes = vec![id];
        for &(namespace, name) in steps {
            nodes = nodes
                .into_iter()
                .flat_map(|id| self.children(id, namespace, name))
                .collect();
        }
        nodes
    }
    pub fn all_path(&self, steps: &[Name]) -> Vec<NodeId> {
        let Some((&(namespace, name), rest)) = steps.split_first() else {
            return Vec::new();
        };
        let mut nodes: Vec<_> = self
            .all(namespace, name)
            .into_iter()
            .flat_map(|id| self.path(id, rest))
            .collect();
        nodes.sort_unstable();
        nodes.dedup();
        nodes
    }
    pub fn attribute(&self, id: NodeId, namespace: &str, name: &str) -> Option<&str> {
        self.node(id)
            .attributes
            .get(&(namespace.to_owned(), name.to_owned()))
            .map(String::as_str)
    }
    pub fn singleton_text(&self, nodes: &[NodeId]) -> Result<Option<&str>, FailureKind> {
        match nodes {
            [] => Ok(None),
            [id] => Ok(Some(&self.node(*id).text)),
            _ => Err(FailureKind::Cardinality),
        }
    }
}

/// No resource resolver is ever invoked: reject DTDs before calling libxml2.
/// Preflight bounds depth/node count before building the DOM and checks names
/// whose namespace errors libxml2 can otherwise report without rejecting a tree.
fn preflight(input: &str, limits: &Limits) -> Result<(), FailureKind> {
    if input.len() > limits.xml_bytes {
        return Err(FailureKind::Limit("XML input bytes"));
    }
    let mut reader = NsReader::from_str(input);
    reader.config_mut().check_comments = true;
    let mut depth = 0usize;
    let mut nodes = 0usize;
    loop {
        let (namespace, event) = reader
            .read_resolved_event()
            .map_err(|e| FailureKind::InvalidXml(e.to_string()))?;
        if matches!(namespace, ResolveResult::Unknown(_)) {
            return Err(FailureKind::InvalidXml("undeclared element prefix".into()));
        }
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::DocType(_) => {
                return Err(FailureKind::UnsupportedXml("DTD declarations".into()));
            }
            Event::Start(element) | Event::Empty(element) => {
                nodes += 1;
                if nodes > limits.nodes {
                    return Err(FailureKind::Limit("XML nodes"));
                }
                if depth + 1 > limits.depth.min(128) {
                    return Err(FailureKind::Limit("XML depth"));
                }
                let mut names = HashSet::new();
                for attr in element.attributes() {
                    let attr = attr.map_err(|e| FailureKind::InvalidXml(e.to_string()))?;
                    if attr.key.as_ref() == b"xmlns" || attr.key.as_ref().starts_with(b"xmlns:") {
                        continue;
                    }
                    let (namespace, name) = reader.resolver().resolve_attribute(attr.key);
                    let namespace = match namespace {
                        ResolveResult::Bound(ns) => ns.as_ref().to_vec(),
                        ResolveResult::Unbound => Vec::new(),
                        ResolveResult::Unknown(_) => {
                            return Err(FailureKind::InvalidXml(
                                "undeclared attribute prefix".into(),
                            ));
                        }
                    };
                    if !names.insert((namespace, name.as_ref().to_vec())) {
                        return Err(FailureKind::InvalidXml(
                            "duplicate expanded attribute name".into(),
                        ));
                    }
                }
                if !empty {
                    depth += 1;
                }
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| FailureKind::InvalidXml("unexpected closing tag".into()))?;
            }
            Event::Decl(decl) => {
                let version = decl
                    .version()
                    .map_err(|e| FailureKind::InvalidXml(e.to_string()))?;
                if version.as_ref() != b"1.0" {
                    return Err(FailureKind::UnsupportedXml(
                        "XML version other than 1.0".into(),
                    ));
                }
                if let Some(encoding) = decl.encoding() {
                    let encoding = encoding.map_err(|e| FailureKind::InvalidXml(e.to_string()))?;
                    if !encoding.eq_ignore_ascii_case(b"UTF-8") {
                        return Err(FailureKind::UnsupportedXml(
                            "input must declare UTF-8".into(),
                        ));
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 {
        return Err(FailureKind::InvalidXml("unclosed element".into()));
    }
    Ok(())
}

pub(super) fn is_xml_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}
pub(super) fn normalize_space(value: &str) -> String {
    value
        .split(is_xml_space)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn xpath_literal(value: &str) -> String {
    if !value.contains('\'') {
        format!("'{value}'")
    } else if !value.contains('"') {
        format!("\"{value}\"")
    } else {
        format!(
            "concat({})",
            value
                .split('\'')
                .map(|part| format!("'{part}'"))
                .collect::<Vec<_>>()
                .join(",\"'\",")
        )
    }
}
