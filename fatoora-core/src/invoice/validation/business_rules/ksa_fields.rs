//! Field predicates translated from the pinned SDK KSA profile (LGPL-3.0).
//! Executable guards and literal whitespace intentionally follow the catalog.
use super::{
    FailureKind,
    decimal::parse_double,
    identity::singleton_attribute,
    structural::indicator,
    xml::{CAC, CBC, NodeId, UBL, XmlView, a, b, normalize_space},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum KsaFieldCheck {
    InvoiceType,
    TransactionCode,
    TransactionLength,
    Profile,
    TaxSubtotalTotal,
    BasePercentage,
    PercentageBase,
    NoPriceCharge,
    BaseUnitLength,
    PositiveBaseQuantity,
}

impl KsaFieldCheck {
    pub fn contexts(self, xml: &XmlView) -> Vec<NodeId> {
        use KsaFieldCheck::*;
        match self {
            InvoiceType | TransactionCode | TransactionLength => xml.all(CBC, "InvoiceTypeCode"),
            Profile | TaxSubtotalTotal => {
                if xml.is(0, UBL, "Invoice") {
                    vec![0]
                } else {
                    Vec::new()
                }
            }
            BasePercentage => {
                // The source's Invoice step is unanchored; a nested UBL Invoice
                // matches too. CreditNote's document allowances do not match.
                let mut nodes =
                    xml.all_path(&[(UBL, "Invoice"), a("AllowanceCharge"), b("BaseAmount")]);
                nodes.extend(xml.all_path(&[
                    a("InvoiceLine"),
                    a("AllowanceCharge"),
                    b("BaseAmount"),
                ]));
                nodes.sort_unstable();
                nodes.dedup();
                nodes
            }
            PercentageBase => xml.all_path(&[a("AllowanceCharge"), b("MultiplierFactorNumeric")]),
            NoPriceCharge => xml.all_path(&[a("InvoiceLine"), a("Price"), a("AllowanceCharge")]),
            BaseUnitLength => xml.all(CAC, "InvoiceLine"),
            PositiveBaseQuantity => {
                xml.all_path(&[a("InvoiceLine"), a("Price"), b("BaseQuantity")])
            }
        }
    }

    pub fn passes(self, xml: &XmlView, node: NodeId) -> Result<bool, FailureKind> {
        use KsaFieldCheck::*;
        Ok(match self {
            InvoiceType => {
                let value = normalize_space(&xml.node(node).text);
                // Both trailing spaces are significant: normalized empty text
                // matches this executable list, unlike the reported test.
                !value.contains(' ') && " 388 383 381 386  ".contains(&format!(" {value} "))
            }
            TransactionCode => {
                let name = xml.attribute(node, "", "name").unwrap_or("");
                (7..=9).contains(&name.chars().count())
                    && (name.starts_with("01") || name.starts_with("02"))
                    && name.chars().skip(2).all(|c| c == '0' || c == '1')
            }
            TransactionLength => (7..=9).contains(
                &xml.attribute(node, "", "name")
                    .unwrap_or("")
                    .chars()
                    .count(),
            ),
            Profile => {
                let profiles = xml.path(node, &[b("ProfileID")]);
                !profiles.is_empty()
                    && normalize_space(xml.singleton_text(&profiles)?.unwrap_or(""))
                        == "reporting:1.0"
            }
            TaxSubtotalTotal => {
                xml.path(node, &[a("TaxTotal")])
                    .into_iter()
                    .filter(|&total| !xml.path(total, &[a("TaxSubtotal")]).is_empty())
                    .count()
                    == 1
            }
            BasePercentage | PercentageBase => {
                let parent = xml.node(node).parent.expect("selected allowance child");
                let required = if matches!(self, BasePercentage) {
                    "MultiplierFactorNumeric"
                } else {
                    "BaseAmount"
                };
                !xml.path(parent, &[b(required)]).is_empty()
            }
            NoPriceCharge => !indicator(xml, node, true)?,
            BaseUnitLength => {
                singleton_attribute(
                    xml,
                    &xml.path(node, &[a("Price"), b("BaseQuantity")]),
                    "unitCode",
                )?
                .chars()
                .count()
                    <= 127
            }
            PositiveBaseQuantity => {
                let value = &xml.node(node).text;
                // fn:number converts invalid lexical input to NaN, so it yields
                // a failed assertion here rather than an evaluation error.
                value.is_empty() || parse_double(value).unwrap_or(f64::NAN) > 0.0
            }
        })
    }
}
