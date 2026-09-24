//! XML preimages for local signature verification. No invoice-model round trip.
use base64ct::{Base64, Encoding};
use libxml::{
    parser::{Parser, ParserOptions},
    tree::{
        Document, Node, NodeType,
        c14n::{CanonicalizationMode, CanonicalizationOptions},
    },
};
use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const EXT: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";
const CAC: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";
const CBC: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const XML: &str = "http://www.w3.org/XML/1998/namespace";
const OUTPUT_LIMIT: usize = 64 * 1024 * 1024;

fn document(xml: &str) -> Result<Document, String> {
    super::business_rules::check_input(xml).map_err(|e| format!("XML preflight: {e:?}"))?;
    Parser::default()
        .parse_string_with_options(
            xml,
            ParserOptions {
                recover: false,
                no_net: true,
                huge: false,
                ..ParserOptions::default()
            },
        )
        .map_err(|e| format!("XML parse: {e}"))
}

fn is(node: &Node, namespace: &str, local: &str) -> bool {
    node.get_type() == Some(NodeType::ElementNode)
        && node.get_name() == local
        && node
            .get_namespace()
            .is_some_and(|ns| ns.get_href() == namespace)
}

pub(super) fn invoice_digest(xml: &str) -> Result<String, String> {
    let doc = document(xml)?;
    let root = doc.get_root_element().ok_or("missing document element")?;
    let mut remaining = vec![root];
    while let Some(mut node) = remaining.pop() {
        let excluded = is(&node, EXT, "UBLExtensions")
            || is(&node, CAC, "Signature")
            || (is(&node, CAC, "AdditionalDocumentReference")
                && node
                    .get_child_elements()
                    .iter()
                    .any(|id| is(id, CBC, "ID") && id.get_content() == "QR"));
        if excluded {
            // Do not retain or visit descendants of a detached exclusion.
            node.unlink();
        } else {
            remaining.extend(node.get_child_elements());
        }
    }
    let canonical = doc
        .canonicalize(
            CanonicalizationOptions {
                mode: CanonicalizationMode::Canonical1_1,
                inclusive_ns_prefixes: vec![],
                with_comments: false,
            },
            None,
        )
        .map_err(|_| "invoice canonicalization failed")?;
    Ok(Base64::encode_string(&Sha256::digest(canonical.as_bytes())))
}

pub(super) fn properties_preimage(xml: &str) -> Result<String, String> {
    let doc = document(xml)?;
    let root = doc.get_root_element().ok_or("missing document element")?;
    let mut remaining = vec![root];
    let mut selected = None;
    while let Some(node) = remaining.pop() {
        if is(&node, XADES, "SignedProperties") {
            let mut ancestor = node.get_parent();
            let mut matches = true;
            for (namespace, local) in [
                (XADES, "QualifyingProperties"),
                (DS, "Object"),
                (DS, "Signature"),
            ] {
                match ancestor {
                    Some(parent) if is(&parent, namespace, local) => ancestor = parent.get_parent(),
                    _ => {
                        matches = false;
                        break;
                    }
                }
            }
            if matches && selected.replace(node.clone()).is_some() {
                return Err("multiple signature SignedProperties subtrees".into());
            }
        }
        remaining.extend(node.get_child_elements());
    }
    let node = selected.ok_or("missing signature SignedProperties subtree")?;
    let mut ancestors = vec![];
    let mut parent = node.get_parent();
    while let Some(node) = parent {
        parent = node.get_parent();
        ancestors.push(node);
    }
    let mut inherited = initial_scope();
    for ancestor in ancestors.iter().rev() {
        for ns in ancestor.get_namespace_declarations() {
            inherited.insert(ns.get_prefix(), ns.get_href());
        }
    }
    // libxml preserves DOM text, CDATA, comments, attribute order and QNames.
    // The second pass supplies namespace declarations using the SDK's
    // standalone DOM serialization rules, rather than changing tag prefixes.
    standalone(&doc.node_to_string(&node), inherited)
}

type Scope = BTreeMap<String, String>;
type Changes = Vec<(String, Option<String>)>;
fn restore(scope: &mut Scope, changes: Changes) {
    for (prefix, old) in changes.into_iter().rev() {
        if let Some(uri) = old {
            scope.insert(prefix, uri);
        } else {
            scope.remove(&prefix);
        }
    }
}
fn initial_scope() -> Scope {
    [(String::new(), String::new()), ("xml".into(), XML.into())].into()
}

struct Output(String);
impl Output {
    fn push(&mut self, value: &str) -> Result<(), String> {
        if value.len() > OUTPUT_LIMIT.saturating_sub(self.0.len()) {
            return Err("SignedProperties serialization exceeds byte limit".into());
        }
        self.0.push_str(value);
        Ok(())
    }
    fn escaped(&mut self, value: &str, attribute: bool) -> Result<(), String> {
        for c in value.chars() {
            self.push(match c {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                '"' if attribute => "&quot;",
                _ => {
                    let mut bytes = [0; 4];
                    self.push(c.encode_utf8(&mut bytes))?;
                    continue;
                }
            })?;
        }
        Ok(())
    }
    fn namespace(
        &mut self,
        prefix: &str,
        uri: &str,
        scope: &mut Scope,
        changes: &mut Changes,
    ) -> Result<(), String> {
        if scope.get(prefix).is_some_and(|current| current == uri) {
            return Ok(());
        }
        self.push(" xmlns")?;
        if !prefix.is_empty() {
            self.push(":")?;
            self.push(prefix)?;
        }
        self.push("=\"")?;
        // The pinned DOM4J XMLWriter writes namespace URIs directly; normal
        // attributes and text use its separate escaping rules.
        self.push(uri)?;
        self.push("\"")?;
        changes.push((prefix.into(), scope.insert(prefix.into(), uri.into())));
        Ok(())
    }
}

fn utf8(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|e| e.to_string())
}

fn namespace_prefix(name: &str) -> Option<&str> {
    if name == "xmlns" {
        Some("")
    } else {
        name.strip_prefix("xmlns:")
    }
}

fn start(
    event: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    source: &mut Scope,
    emitted: &mut Scope,
    output: &mut Output,
    source_changes: &mut Changes,
    emitted_changes: &mut Changes,
) -> Result<bool, String> {
    let qname = event.name();
    let name = utf8(qname.as_ref())?;
    let attributes: Vec<_> = event
        .attributes()
        .map(|a| {
            let a = a.map_err(|e| e.to_string())?;
            Ok((
                utf8(a.key.as_ref())?.to_owned(),
                a.decode_and_unescape_value(reader.decoder())
                    .map_err(|e| e.to_string())?
                    .into_owned(),
            ))
        })
        .collect::<Result<_, String>>()?;
    for (key, value) in &attributes {
        if let Some(prefix) = namespace_prefix(key) {
            source_changes.push((prefix.into(), source.insert(prefix.into(), value.clone())));
        }
    }
    output.push("<")?;
    output.push(name)?;
    let prefix = name.split_once(':').map_or("", |(prefix, _)| prefix);
    let uri = source.get(prefix).ok_or("undeclared element namespace")?;
    output.namespace(prefix, uri, emitted, emitted_changes)?;
    let mut declarations = false;
    for (key, value) in &attributes {
        if let Some(prefix) = namespace_prefix(key) {
            declarations = true;
            output.namespace(prefix, value, emitted, emitted_changes)?;
        }
    }
    for (key, value) in &attributes {
        if namespace_prefix(key).is_some() {
            continue;
        }
        if let Some((prefix, _)) = key.split_once(':') {
            let uri = source.get(prefix).ok_or("undeclared attribute namespace")?;
            output.namespace(prefix, uri, emitted, emitted_changes)?;
        }
        output.push(" ")?;
        output.push(key)?;
        output.push("=\"")?;
        output.escaped(value, true)?;
        output.push("\"")?;
    }
    Ok(declarations)
}

fn standalone(raw: &str, inherited: Scope) -> Result<String, String> {
    let mut reader = Reader::from_str(raw);
    let mut source = inherited;
    let mut emitted = initial_scope();
    let mut stack = vec![];
    let mut output = Output(String::new());
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(event) => {
                let mut source_changes = vec![];
                let mut emitted_changes = vec![];
                start(
                    &event,
                    &reader,
                    &mut source,
                    &mut emitted,
                    &mut output,
                    &mut source_changes,
                    &mut emitted_changes,
                )?;
                stack.push((source_changes, emitted_changes));
                output.push(">")?;
            }
            Event::Empty(event) => {
                let mut source_changes = vec![];
                let mut emitted_changes = vec![];
                let declarations = start(
                    &event,
                    &reader,
                    &mut source,
                    &mut emitted,
                    &mut output,
                    &mut source_changes,
                    &mut emitted_changes,
                )?;
                restore(&mut source, source_changes);
                restore(&mut emitted, emitted_changes);
                if declarations {
                    // DOM4J counts explicitly declared namespaces as content.
                    output.push("></")?;
                    output.push(utf8(event.name().as_ref())?)?;
                    output.push(">")?;
                } else {
                    output.push("/>")?;
                }
            }
            Event::End(event) => {
                output.push("</")?;
                output.push(utf8(event.name().as_ref())?)?;
                output.push(">")?;
                let (source_changes, emitted_changes) =
                    stack.pop().ok_or("unbalanced SignedProperties")?;
                restore(&mut source, source_changes);
                restore(&mut emitted, emitted_changes);
            }
            Event::Text(event) => {
                output.escaped(&event.decode().map_err(|e| e.to_string())?, false)?
            }
            Event::GeneralRef(event) => {
                let name = event.decode().map_err(|e| e.to_string())?;
                let encoded = format!("&{name};");
                let value = quick_xml::escape::unescape(&encoded).map_err(|e| e.to_string())?;
                output.escaped(&value, false)?;
            }
            Event::CData(event) => {
                output.push("<![CDATA[")?;
                output.push(utf8(event.as_ref())?)?;
                output.push("]]>")?;
            }
            Event::Comment(event) => {
                output.push("<!--")?;
                output.push(utf8(event.as_ref())?)?;
                output.push("-->")?;
            }
            Event::PI(event) => {
                output.push("<?")?;
                output.push(utf8(event.as_ref())?)?;
                output.push("?>")?;
            }
            Event::Eof => break,
            _ => return Err("unexpected SignedProperties document event".into()),
        }
    }
    Ok(output.0)
}
