//! Pinned KSA exemption/category predicates; translated expressions retain LGPL-3.0.
//! Template039 deliberately repeats its global loops for every outer S context.
use super::{
    FailureKind,
    decimal::parse_double,
    identity::optional_length,
    structural::{indicator, is_vat},
    xml::{Name, NodeId, UBL, XmlView, a, b, normalize_space},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum KsaExemptionCheck {
    VatCategoryCode,
    ExemptionReasonLength,
    MimeCode,
    ExemptionReason,
    ExemptionCode,
    OutsideScopeCode,
    ExemptCode,
    ZeroRatedCode,
    AllowanceStandardRate,
    BreakdownStandardRate,
    ItemStandardRate,
    PrepaymentStandardRate,
    PrepaymentZeroRatedCode,
    PrepaymentExemptCode,
    PrepaymentOutsideScopeCode,
    PrepaymentExemptionReason,
    PrepaymentExemptionCode,
    PrepaymentExemptionReasonLength,
}

impl KsaExemptionCheck {
    /// Context selection itself evaluates singleton/cast predicates and can fail.
    /// Repeated node IDs are distinct source occurrences and must not be deduped.
    pub fn contexts(self, xml: &XmlView) -> Result<Vec<NodeId>, FailureKind> {
        use KsaExemptionCheck::*;
        match self {
            VatCategoryCode => {
                if !xml.is(0, UBL, "Invoice") {
                    return Ok(Vec::new());
                }
                let mut nodes = Vec::new();
                for path in [BREAKDOWN, PREPAYMENT, ALLOWANCE, ITEM] {
                    let mut path = path.to_vec();
                    path.push(b("ID"));
                    nodes.extend(xml.path(0, &path));
                }
                nodes.sort_unstable();
                nodes.dedup();
                Ok(nodes)
            }
            ExemptionReasonLength => select_categories(xml, xml.path(0, BREAKDOWN), "ZEO", false),
            MimeCode => Ok(xml.all_path(&[
                a("AdditionalDocumentReference"),
                a("Attachment"),
                b("EmbeddedDocumentBinaryObject"),
            ])),
            ExemptionReason | ExemptionCode | OutsideScopeCode | ExemptCode | ZeroRatedCode => {
                let mut path = vec![(UBL, "Invoice")];
                path.extend_from_slice(BREAKDOWN);
                select_categories(xml, xml.all_path(&path), "ZEO", false)
            }
            _ => {
                // The outer union is unanchored, unlike each inner for-each.
                // Evaluate its guards even when the selected inner loop is empty.
                let outer = standard_contexts(xml)?;
                if outer.is_empty() || !xml.is(0, UBL, "Invoice") {
                    return Ok(Vec::new());
                }
                let (path, categories) = match self {
                    AllowanceStandardRate => (ALLOWANCE, "S"),
                    BreakdownStandardRate => (BREAKDOWN, "S"),
                    ItemStandardRate => (ITEM, "S"),
                    PrepaymentStandardRate => (PREPAYMENT, "S"),
                    PrepaymentZeroRatedCode => (PREPAYMENT, "Z"),
                    PrepaymentExemptCode => (PREPAYMENT, "E"),
                    PrepaymentOutsideScopeCode => (PREPAYMENT, "O"),
                    PrepaymentExemptionReason
                    | PrepaymentExemptionCode
                    | PrepaymentExemptionReasonLength => (PREPAYMENT, "ZEO"),
                    _ => unreachable!(),
                };
                let inner = select_categories(xml, xml.path(0, path), categories, true)?;
                // Until the public Limits contract gains an occurrence bound,
                // bound this Cartesian allocation independently of finding count.
                let count = outer
                    .len()
                    .checked_mul(inner.len())
                    .filter(|&count| count <= 100_000)
                    .ok_or(FailureKind::Limit("rule context occurrences"))?;
                let mut occurrences = Vec::with_capacity(count);
                for _ in outer {
                    occurrences.extend_from_slice(&inner);
                }
                Ok(occurrences)
            }
        }
    }

    pub fn passes(self, xml: &XmlView, node: NodeId, _digits: usize) -> Result<bool, FailureKind> {
        use KsaExemptionCheck::*;
        match self {
            VatCategoryCode => Ok(" S Z E O ".contains(&xml.node(node).text)),
            ExemptionReasonLength | PrepaymentExemptionReasonLength => {
                optional_length(xml, &xml.path(node, &[b("TaxExemptionReason")]), 1, 1000)
            }
            MimeCode => {
                let mime = normalize_space(xml.attribute(node, "", "mimeCode").unwrap_or(""));
                Ok(!mime.contains(' ') && MIME_CODES.contains(&format!(" {mime} ")))
            }
            ExemptionReason | PrepaymentExemptionReason => {
                if xml.path(node, &[b("TaxExemptionReasonCode")]).is_empty() {
                    return Ok(true);
                }
                Ok(!normalized_child(xml, node, "TaxExemptionReason")?.is_empty())
            }
            ExemptionCode | PrepaymentExemptionCode => {
                exemption_code(xml, node, matches!(self, ExemptionCode))
            }
            OutsideScopeCode | ExemptCode | ZeroRatedCode => {
                let category = match self {
                    OutsideScopeCode => "O",
                    ExemptCode => "E",
                    ZeroRatedCode => "Z",
                    _ => unreachable!(),
                };
                Ok(normalized_child(xml, node, "ID")? != category
                    || !normalized_child(xml, node, "TaxExemptionReasonCode")?.is_empty())
            }
            PrepaymentZeroRatedCode | PrepaymentExemptCode | PrepaymentOutsideScopeCode => {
                Ok(!normalized_child(xml, node, "TaxExemptionReasonCode")?.is_empty())
            }
            AllowanceStandardRate
            | BreakdownStandardRate
            | ItemStandardRate
            | PrepaymentStandardRate => {
                let percentages = xml.path(node, &[b("Percent")]);
                let Some(percent) = xml.singleton_text(&percentages)? else {
                    return Ok(true);
                };
                // Executable source: floor(number(Percent)) = 15 OR
                // floor(number(Percent = 5)). The second branch converts a
                // boolean to 0/1, accepting exactly 5, not floor(Percent) = 5.
                // fn:number masks invalid lexical values as NaN; the subsequent
                // untypedAtomic general comparison to 5 raises a cast error.
                Ok(parse_double(percent).unwrap_or(f64::NAN).floor() == 15.0
                    || parse_double(percent)? == 5.0)
            }
        }
    }
}

fn normalized_child(
    xml: &XmlView,
    node: NodeId,
    name: &'static str,
) -> Result<String, FailureKind> {
    Ok(normalize_space(
        xml.singleton_text(&xml.path(node, &[b(name)]))?
            .unwrap_or(""),
    ))
}

fn select_categories(
    xml: &XmlView,
    candidates: Vec<NodeId>,
    categories: &str,
    vat: bool,
) -> Result<Vec<NodeId>, FailureKind> {
    let mut selected = Vec::new();
    for node in candidates {
        let code = normalized_child(xml, node, "ID")?;
        // These are equality comparisons, unlike site's 061 substring check.
        if categories
            .chars()
            .any(|category| code == category.to_string())
            && (!vat || is_vat(xml, node)?)
        {
            selected.push(node);
        }
    }
    Ok(selected)
}

fn standard_contexts(xml: &XmlView) -> Result<Vec<NodeId>, FailureKind> {
    let mut candidates = Vec::new();
    for node in xml.all_path(ALLOWANCE) {
        let allowance = xml.node(node).parent.expect("selected tax category parent");
        if indicator(xml, allowance, false)? || indicator(xml, allowance, true)? {
            candidates.push(node);
        }
    }
    candidates.extend(xml.all_path(BREAKDOWN));
    candidates.extend(xml.all_path(ITEM));
    // PREPAYMENT is a subset of the unanchored BREAKDOWN arm. A union selects
    // it only once, regardless of how many arms match that same node.
    candidates.sort_unstable();
    candidates.dedup();
    select_categories(xml, candidates, "S", true)
}

fn exemption_code(xml: &XmlView, node: NodeId, document: bool) -> Result<bool, FailureKind> {
    let code = normalized_child(xml, node, "TaxExemptionReasonCode")?;
    // The executable expression has a final empty-string disjunct. Missing or
    // empty codes pass this list check; separate presence assertions reject them.
    if code.is_empty() {
        return Ok(true);
    }
    if code.contains(' ') {
        return Ok(false);
    }
    let category = normalized_child(xml, node, "ID")?;
    let allowed = match category.as_str() {
        "Z" if document => ZERO_CODES,
        "Z" => PREPAYMENT_ZERO_CODES,
        "E" => " VATEX-SA-29 VATEX-SA-29-7 VATEX-SA-30 ",
        "O" => " VATEX-SA-OOS ",
        _ => return Ok(false),
    };
    Ok(allowed.contains(&format!(" {code} ")))
}

const BREAKDOWN: &[Name] = &[a("TaxTotal"), a("TaxSubtotal"), a("TaxCategory")];
const PREPAYMENT: &[Name] = &[
    a("InvoiceLine"),
    a("TaxTotal"),
    a("TaxSubtotal"),
    a("TaxCategory"),
];
const ALLOWANCE: &[Name] = &[a("AllowanceCharge"), a("TaxCategory")];
const ITEM: &[Name] = &[a("InvoiceLine"), a("Item"), a("ClassifiedTaxCategory")];
const MIME_CODES: &str = " text/csv text/plain application/pdf image/png image/jpeg image/tiff application/acad application/dwg drawing/dwg application/vnd.openxmlformats-officedocument.spreadsheetml.sheet application/vnd.oasis.opendocument.spreadsheet ";
const ZERO_CODES: &str = " VATEX-SA-32 VATEX-SA-33 VATEX-SA-34-1 VATEX-SA-34-2 VATEX-SA-34-3 VATEX-SA-34-4 VATEX-SA-34-5 VATEX-SA-35 VATEX-SA-36 VATEX-SA-EDU VATEX-SA-HEA VATEX-SA-MLTRY VATEX-SA-DIPLOMAT VATEX-SA-DUTYFREE VATEX-SA-ROYALDECREE VATEX-SA-32(bis) ";
const PREPAYMENT_ZERO_CODES: &str = " VATEX-SA-32 VATEX-SA-33 VATEX-SA-34-1 VATEX-SA-34-2 VATEX-SA-34-3 VATEX-SA-34-4 VATEX-SA-34-5 VATEX-SA-35 VATEX-SA-36 VATEX-SA-EDU VATEX-SA-HEA VATEX-SA-MLTRY VATEX-SA-DIPLOMAT VATEX-SA-DUTYFREE ";
