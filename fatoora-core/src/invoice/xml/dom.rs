//! Shared XML DOM and XPath helpers built on [`uppsala`].
//!
//! Every invoice XPath in this crate uses the UBL prefixes (`ubl`, `cbc`,
//! `cac`, ...), so [`evaluator`] hands out one shared evaluator with all of
//! them bound. The rest of the module smooths over the two places where
//! uppsala's API differs from what the call sites want: attribute nodes need
//! their own string-value path, and setting an element's text means replacing
//! its children rather than assigning to it.

use std::sync::OnceLock;

use uppsala::{Document, NodeId, NodeKind, XPathEvaluator, XPathValue, XmlResult};

use super::constants::{
    CAC_NS, CBC_NS, DS_NS, EXT_NS, INVOICE_NS, SAC_NS, SBC_NS, SIG_NS, XADES_NS,
};

/// Parse an invoice document and ready it for XPath evaluation.
///
/// The document borrows `xml`, so it must not outlive the source text. That is
/// the cheap direction: taking ownership would deep-copy every name and text
/// node in the tree.
pub(crate) fn parse(xml: &str) -> XmlResult<Document<'_>> {
    let mut doc = uppsala::parse(xml)?;
    doc.prepare_xpath();
    Ok(doc)
}

/// Node-visit budget for a single XPath evaluation.
///
/// uppsala defaults to 100,000 visits, which a real invoice can exhaust: every
/// `//`-rooted expression charges one visit per node walked, so hashing an
/// invoice with a couple of thousand lines fails outright. The budget still
/// bounds a runaway expression — visits are cheap, so this ceiling is seconds
/// of work, not minutes — while leaving any plausible invoice far below it.
const MAX_XPATH_NODE_VISITS: usize = 50_000_000;

/// The shared evaluator, with every UBL/XAdES prefix this crate uses bound.
///
/// Bindings are fixed, so the prefix map is built once rather than per query;
/// signing alone would otherwise rebuild it several times per invoice.
pub(crate) fn evaluator() -> &'static XPathEvaluator {
    static EVALUATOR: OnceLock<XPathEvaluator> = OnceLock::new();

    EVALUATOR.get_or_init(|| {
        let mut eval = XPathEvaluator::new().with_max_node_visits(MAX_XPATH_NODE_VISITS);
        for (prefix, uri) in [
            ("ubl", INVOICE_NS),
            ("cbc", CBC_NS),
            ("cac", CAC_NS),
            ("ext", EXT_NS),
            ("sig", SIG_NS),
            ("sac", SAC_NS),
            ("sbc", SBC_NS),
            ("ds", DS_NS),
            ("xades", XADES_NS),
        ] {
            eval.add_namespace(prefix, uri);
        }
        eval
    })
}

/// Evaluate `expr` against the whole document, returning matches in document order.
pub(crate) fn nodes(
    eval: &XPathEvaluator,
    doc: &Document<'_>,
    expr: &str,
) -> XmlResult<Vec<NodeId>> {
    nodes_from(eval, doc, doc.root(), expr)
}

/// Evaluate `expr` with `context` as the context node.
///
/// Relative expressions are the way to walk a repeated element such as
/// `cac:InvoiceLine`: uppsala's XPath parser does not accept a location step
/// after a parenthesised filter, so `(//cac:InvoiceLine)[2]/cbc:ID` has to be
/// expressed as `cbc:ID` evaluated from the second line node.
///
/// A non-node-set result (a number, string, or boolean) yields an empty vector
/// rather than an error; every caller here queries for nodes.
pub(crate) fn nodes_from(
    eval: &XPathEvaluator,
    doc: &Document<'_>,
    context: NodeId,
    expr: &str,
) -> XmlResult<Vec<NodeId>> {
    match eval.evaluate(doc, context, expr)? {
        XPathValue::NodeSet(nodes) => Ok(nodes),
        _ => Ok(Vec::new()),
    }
}

/// String value of a node, handling attributes as well as elements.
///
/// `text_content_deep` walks children, so it returns an empty string for the
/// virtual attribute nodes XPath produces for `@name`-style steps. Those carry
/// their value in the node itself.
pub(crate) fn string_value(doc: &Document<'_>, id: NodeId) -> String {
    match doc.node_kind(id) {
        Some(NodeKind::Attribute(_, value)) => value.to_string(),
        _ => doc.text_content_deep(id),
    }
}

/// Trimmed text of the first node matching `expr`.
///
/// Returns `None` when nothing matches or the value is blank, so callers that
/// have no use for the difference can treat "absent" and "empty" alike. Use
/// [`text_present`] where the distinction belongs in the error message.
pub(crate) fn text(
    eval: &XPathEvaluator,
    doc: &Document<'_>,
    expr: &str,
) -> XmlResult<Option<String>> {
    text_from(eval, doc, doc.root(), expr)
}

/// Trimmed text of the first node matching `expr`, evaluated from `context`.
pub(crate) fn text_from(
    eval: &XPathEvaluator,
    doc: &Document<'_>,
    context: NodeId,
    expr: &str,
) -> XmlResult<Option<String>> {
    Ok(text_present_from(eval, doc, context, expr)?.filter(|value| !value.is_empty()))
}

/// Trimmed text of the first node matching `expr`, keeping "present but blank".
///
/// `None` means nothing matched; `Some("")` means an element is there and
/// empty. The QR and signing paths report those two cases differently — telling
/// an operator a field is missing when it is present and blank sends them
/// looking for an element that is right in front of them.
pub(crate) fn text_present(
    eval: &XPathEvaluator,
    doc: &Document<'_>,
    expr: &str,
) -> XmlResult<Option<String>> {
    text_present_from(eval, doc, doc.root(), expr)
}

/// [`text_present`], evaluated from `context`.
pub(crate) fn text_present_from(
    eval: &XPathEvaluator,
    doc: &Document<'_>,
    context: NodeId,
    expr: &str,
) -> XmlResult<Option<String>> {
    let Some(id) = nodes_from(eval, doc, context, expr)?.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(string_value(doc, id).trim().to_string()))
}

/// Replace an element's children with a single text node.
///
/// uppsala has no `set_content`, and the elements this targets hold nothing but
/// text, so dropping the existing children is the faithful equivalent.
pub(crate) fn set_text<'a>(doc: &mut Document<'a>, id: NodeId, value: &str) {
    for child in doc.children(id) {
        doc.detach(child);
    }
    let text = doc.create_text(value.to_string());
    doc.append_child(id, text);
}

/// Parse a template fragment and graft its root element into `doc`.
///
/// Returns the imported node, still detached; the caller decides where it goes.
pub(crate) fn import_fragment<'a>(doc: &mut Document<'a>, xml: &str) -> XmlResult<Option<NodeId>> {
    let fragment = uppsala::parse(xml)?;
    let Some(root) = fragment.document_element() else {
        return Ok(None);
    };
    Ok(doc.import_subtree(&fragment, root))
}
