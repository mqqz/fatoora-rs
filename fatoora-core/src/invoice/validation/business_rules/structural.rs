//! Native structural predicates from the pinned SDK CEN profile (LGPL-3.0).
use super::{
    FailureKind,
    identity::{optional_length, singleton_attribute},
    xml::{CAC, Name, NodeId, UBL, XmlView, a, b, normalize_space},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum Context {
    Root,
    All(&'static [Name]),
    InvoicePath(&'static [Name]),
    Lines,
    DocumentAllowance(bool),
    LineCharge,
    LineAllowance,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Requirement {
    Exists(&'static [Name]),
    Nonempty(&'static [Name]),
    Length(&'static [Name], usize, usize),
    AttributeLength(&'static [Name], &'static str, usize),
    Scale(&'static [Name]),
    InvoiceType,
    InvoiceNote,
    InvoiceLines,
    TaxAccounting,
    InvoicedQuantity,
    ItemName,
    VatCategory(&'static [Name], bool),
    VatRate,
    ItemVatCategory,
    ItemProperty,
    PaymentCode,
}

impl Context {
    pub fn nodes(self, xml: &XmlView) -> Vec<NodeId> {
        match self {
            Self::Root => vec![0],
            Self::All(path) => xml.all_path(path),
            Self::InvoicePath(path) => {
                if xml.is(0, UBL, "Invoice") {
                    xml.path(0, path)
                } else {
                    Vec::new()
                }
            }
            Self::Lines => {
                let mut nodes = xml.all(CAC, "InvoiceLine");
                nodes.extend(xml.all(CAC, "CreditNoteLine"));
                nodes.sort_unstable();
                nodes
            }
            Self::DocumentAllowance(_) => xml.path(0, &[a("AllowanceCharge")]),
            Self::LineCharge => xml.all_path(&[a("InvoiceLine"), a("AllowanceCharge")]),
            Self::LineAllowance => {
                let mut nodes = xml.all_path(&[a("InvoiceLine"), a("AllowanceCharge")]);
                nodes.extend(xml.all_path(&[a("CreditNoteLine"), a("AllowanceCharge")]));
                nodes.sort_unstable();
                nodes
            }
        }
    }

    pub fn applies(self, xml: &XmlView, node: NodeId) -> Result<bool, FailureKind> {
        match self {
            Self::DocumentAllowance(charge) => {
                // Same priority, same pattern: the later charge template wins
                // if a repeated indicator sequence matches both booleans.
                let is_charge = indicator(xml, node, true)?;
                Ok(if charge {
                    is_charge
                } else {
                    !is_charge && indicator(xml, node, false)?
                })
            }
            Self::LineCharge => indicator(xml, node, true),
            Self::LineAllowance => {
                if !indicator(xml, node, false)? {
                    return Ok(false);
                }
                let parent = xml.node(node).parent.expect("selected line allowance");
                if xml.is(parent, CAC, "InvoiceLine")
                    && (xml
                        .node(parent)
                        .parent
                        .is_some_and(|root| xml.is_document_root(root))
                        || indicator(xml, node, true)?)
                {
                    return Ok(false);
                }
                Ok(true)
            }
            _ => Ok(true),
        }
    }
}

impl Requirement {
    pub fn passes(self, xml: &XmlView, node: NodeId) -> Result<bool, FailureKind> {
        match self {
            Self::Exists(path) => Ok(!xml.path(node, path).is_empty()),
            Self::Nonempty(path) => Ok(xml
                .path(node, path)
                .iter()
                .any(|&id| !xml.node(id).text.is_empty())),
            Self::Length(path, min, max) => optional_length(xml, &xml.path(node, path), min, max),
            Self::AttributeLength(path, attribute, max) => {
                Ok(singleton_attribute(xml, &xml.path(node, path), attribute)?
                    .chars()
                    .count()
                    <= max)
            }
            Self::Scale(path) => scale(xml, &xml.path(node, path)),
            Self::InvoiceType => {
                Ok(["InvoiceTypeCode", "CreditNoteTypeCode"]
                    .iter()
                    .any(|field| {
                        xml.path(node, &[b(field)])
                            .iter()
                            .any(|&id| !xml.node(id).text.is_empty())
                    }))
            }
            Self::InvoiceNote => Ok(!xml.is(0, UBL, "Invoice")
                || !xml.path(0, &[b("Note")]).iter().any(|&id| {
                    xml.node(id)
                        .direct_text
                        .iter()
                        .any(|text| text.chars().count() > 1000)
                })),
            Self::InvoiceLines => Ok(!xml.path(node, &[a("InvoiceLine")]).is_empty()
                || !xml.path(node, &[a("CreditNoteLine")]).is_empty()),
            Self::TaxAccounting => {
                let currencies = xml.path(node, &[b("TaxCurrencyCode")]);
                if currencies.is_empty() {
                    return Ok(true);
                }
                for tax in xml.path(node, &[a("TaxTotal")]) {
                    if !xml.path(tax, &[a("TaxSubtotal")]).is_empty() {
                        continue;
                    }
                    let amounts = xml.path(tax, &[b("TaxAmount")]);
                    if amounts.is_empty() {
                        return Ok(false);
                    }
                    for amount in amounts {
                        if let Some(currency) = xml.attribute(amount, "", "currencyID")
                            && !currencies.iter().any(|&id| xml.node(id).text == currency)
                        {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            }
            Self::InvoicedQuantity => {
                let amounts = xml.path(node, &[b("InvoicedQuantity")]);
                Ok(!amounts.is_empty()
                    && !amounts
                        .iter()
                        .any(|&id| xml.node(id).direct_text.iter().any(|text| text == "0")))
            }
            Self::ItemName => {
                let nodes = xml.path(node, &[a("Item"), b("Name")]);
                Ok(!digits(xml.singleton_text(&nodes)?.unwrap_or("")))
            }
            Self::VatCategory(path, nonempty) => {
                for category in xml.path(node, path) {
                    if is_vat(xml, category)?
                        && xml
                            .path(category, &[b("ID")])
                            .iter()
                            .any(|&id| !nonempty || !xml.node(id).text.is_empty())
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::ItemVatCategory => {
                for category in xml.path(node, &[a("Item"), a("ClassifiedTaxCategory")]) {
                    // BR-CO-04 applies EBV to a sequence of booleans produced by
                    // TaxScheme/(... = 'VAT'), unlike the other VAT predicates.
                    if xml.path(category, &[a("TaxScheme")]).len() > 1 {
                        return Err(FailureKind::Cardinality);
                    }
                    if is_vat(xml, category)? && !xml.path(category, &[b("ID")]).is_empty() {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::VatRate => {
                for category in xml.path(node, &[a("TaxCategory")]) {
                    if is_vat(xml, category)?
                        && (!xml.path(category, &[b("Percent")]).is_empty()
                            || normalize_space(
                                xml.singleton_text(&xml.path(category, &[b("ID")]))?
                                    .unwrap_or(""),
                            ) == "O")
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::ItemProperty => Ok(!xml.path(node, &[b("Name")]).is_empty()
                && !xml.path(node, &[b("Value")]).is_empty()),
            Self::PaymentCode => {
                Ok(!has_transaction(xml, "01")
                    || !xml.path(node, &[b("PaymentMeansCode")]).is_empty())
            }
        }
    }
}

pub(super) fn indicator(xml: &XmlView, node: NodeId, expected: bool) -> Result<bool, FailureKind> {
    for id in xml.path(node, &[b("ChargeIndicator")]) {
        let value = match normalize_space(&xml.node(id).text).as_str() {
            "false" | "0" => false,
            "true" | "1" => true,
            _ => return Err(FailureKind::InvalidBoolean),
        };
        if value == expected {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(super) fn scale(xml: &XmlView, nodes: &[NodeId]) -> Result<bool, FailureKind> {
    Ok(xml
        .singleton_text(nodes)?
        .unwrap_or("")
        .split_once('.')
        .is_none_or(|(_, fraction)| fraction.chars().count() <= 2))
}
pub(super) fn is_vat(xml: &XmlView, category: NodeId) -> Result<bool, FailureKind> {
    for scheme in xml.path(category, &[a("TaxScheme")]) {
        if normalize_space(
            &xml.singleton_text(&xml.path(scheme, &[b("ID")]))?
                .unwrap_or("")
                .to_uppercase(),
        ) == "VAT"
        {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(super) fn digits(value: &str) -> bool {
    static DIGITS: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^\p{Nd}+$").expect("constant regex"));
    DIGITS.is_match(value)
}
pub(super) fn has_transaction(xml: &XmlView, prefix: &str) -> bool {
    // fn:matches searches anywhere, not just at the start or on TypeCode.
    xml.elements().any(|(id, _)| {
        xml.attribute(id, "", "name").is_some_and(|name| {
            name.match_indices(prefix).any(|(offset, _)| {
                let tail = &name[offset + prefix.len()..];
                let five: String = tail.chars().take(5).collect();
                five.chars().count() == 5 && digits(&five)
            })
        })
    })
}
