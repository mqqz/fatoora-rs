//! Currency and lexical numeric checks translated from the pinned KSA profile.
//! Source expressions retain LGPL-3.0 terms recorded in the source catalog.
use super::{
    FailureKind,
    decimal::parse_double,
    patterns::MatchCache,
    xml::{CBC, Name, NodeId, UBL, XmlView, a, b, normalize_space},
};
#[derive(Debug, Clone, Copy)]
pub(super) enum KsaCurrencyCheck {
    CurrencyCode,
    AmountCurrency,
    Boolean,
    Nonnegative,
    ExchangeFields,
    ExchangeSource,
    ExchangeTarget,
    ExchangeRateLength,
}
impl KsaCurrencyCheck {
    pub fn contexts(self, xml: &XmlView) -> Result<Vec<NodeId>, FailureKind> {
        use KsaCurrencyCheck::*;
        let mut nodes = match self {
            CurrencyCode => {
                let mut nodes = xml.all(CBC, "DocumentCurrencyCode");
                for path in [
                    &[
                        a("InvoiceLine"),
                        a("TaxTotal"),
                        a("TaxSubtotal"),
                        b("TaxAmount"),
                    ][..],
                    &[
                        a("InvoiceLine"),
                        a("TaxTotal"),
                        a("TaxSubtotal"),
                        b("TaxableAmount"),
                    ][..],
                    &[a("LegalMonetaryTotal"), b("PayableRoundingAmount")][..],
                ] {
                    nodes.extend(
                        xml.all_path(path)
                            .into_iter()
                            .filter(|&n| xml.attribute(n, "", "currencyID").is_some()),
                    );
                }
                nodes
            }
            AmountCurrency => {
                let mut nodes = xml
                    .elements()
                    .filter(|(_, n)| n.namespace == CBC && AMOUNTS.contains(&n.name.as_str()))
                    .map(|(id, _)| id)
                    .collect::<Vec<_>>();
                for field in ["TaxableAmount", "TaxAmount"] {
                    nodes.extend(xml.all_path(&[
                        (UBL, "Invoice"),
                        a("TaxTotal"),
                        a("TaxSubtotal"),
                        b(field),
                    ]));
                    nodes.extend(xml.all_path(&[
                        a("InvoiceLine"),
                        a("TaxTotal"),
                        a("TaxSubtotal"),
                        b(field),
                    ]));
                }
                for field in ["TaxAmount", "RoundingAmount"] {
                    nodes.extend(xml.all_path(&[a("InvoiceLine"), a("TaxTotal"), b(field)]));
                }
                nodes
            }
            Boolean => xml.all_path(&[a("AllowanceCharge"), b("ChargeIndicator")]),
            Nonnegative => {
                let mut nodes = Vec::new();
                for path in NONNEGATIVE {
                    let mut full = vec![(UBL, "Invoice")];
                    full.extend_from_slice(path);
                    nodes.extend(xml.all_path(&full));
                }
                for sub in xml.all_path(&[(UBL, "Invoice"), a("TaxTotal"), a("TaxSubtotal")]) {
                    if normalize_space(
                        xml.singleton_text(&xml.path(sub, &[a("TaxCategory"), b("ID")]))?
                            .unwrap_or(""),
                    ) != "O"
                    {
                        nodes.extend(xml.path(sub, &[b("TaxableAmount")]));
                    }
                }
                nodes
            }
            _ => {
                let mut nodes = xml.all(CBC, "DocumentCurrencyCode");
                nodes.extend(xml.all(CBC, "TaxCurrencyCode"));
                if xml.is(0, UBL, "Invoice") {
                    nodes.extend(xml.path(0, &[a("TaxExchangeRate")]));
                }
                nodes
            }
        };
        nodes.sort_unstable();
        nodes.dedup();
        Ok(nodes)
    }
    pub fn location(self, xml: &XmlView, node: NodeId) -> String {
        let path = &xml.node(node).location;
        if matches!(self, Self::CurrencyCode) && !xml.is(node, CBC, "DocumentCurrencyCode") {
            format!("{path}/@currencyID")
        } else {
            path.clone()
        }
    }
    pub fn passes(
        self,
        xml: &XmlView,
        node: NodeId,
        patterns: &MatchCache,
    ) -> Result<bool, FailureKind> {
        use KsaCurrencyCheck::*;
        let exchange = |field| {
            if xml.is(0, UBL, "Invoice") {
                xml.path(0, &[a("TaxExchangeRate"), b(field)])
            } else {
                vec![]
            }
        };
        let nonempty = |nodes: &[NodeId]| nodes.iter().any(|&n| !xml.node(n).text.is_empty());
        Ok(match self {
            CurrencyCode => {
                let value = if xml.is(node, CBC, "DocumentCurrencyCode") {
                    &xml.node(node).text
                } else {
                    xml.attribute(node, "", "currencyID")
                        .expect("selected attribute")
                };
                let value = normalize_space(value);
                !value.contains(' ')
                    && super::code_lists::CURRENCIES.contains(&format!(" {value} "))
            }
            AmountCurrency => {
                let Some(pattern) = xml.attribute(node, "", "currencyID") else {
                    return Ok(false);
                };
                let currency = normalize_space(
                    xml.singleton_text(&xml.all(CBC, "DocumentCurrencyCode"))?
                        .unwrap_or(""),
                );
                patterns.matches(&currency, pattern)? && !pattern.is_empty()
            }
            Boolean => match xml.node(node).text.trim_matches(super::xml::is_xml_space) {
                "true" | "false" | "1" | "0" => true,
                _ => return Err(FailureKind::InvalidBoolean),
            },
            Nonnegative => {
                xml.node(node).text.is_empty() || parse_double(&xml.node(node).text)? >= 0.0
            }
            ExchangeFields => {
                !xml.is(0, UBL, "Invoice")
                    || xml.path(0, &[a("TaxExchangeRate")]).is_empty()
                    || [
                        "SourceCurrencyCode",
                        "TargetCurrencyCode",
                        "CalculationRate",
                    ]
                    .iter()
                    .all(|&field| nonempty(&exchange(field)))
            }
            ExchangeSource | ExchangeTarget => {
                let (field, currency) = if matches!(self, ExchangeSource) {
                    ("SourceCurrencyCode", "DocumentCurrencyCode")
                } else {
                    ("TargetCurrencyCode", "TaxCurrencyCode")
                };
                let values = exchange(field);
                if !nonempty(&values) {
                    return Ok(true);
                }
                let pattern = xml.singleton_text(&values)?.unwrap_or("");
                let currency =
                    normalize_space(xml.singleton_text(&xml.all(CBC, currency))?.unwrap_or(""));
                patterns.matches(&currency, pattern)?
            }
            ExchangeRateLength => {
                let values = exchange("CalculationRate");
                !nonempty(&values)
                    || normalize_space(xml.singleton_text(&values)?.unwrap_or(""))
                        .chars()
                        .count()
                        < 15
            }
        })
    }
}
const AMOUNTS: &[&str] = &[
    "Amount",
    "BaseAmount",
    "LineExtensionAmount",
    "PriceAmount",
    "TaxExclusiveAmount",
    "TaxInclusiveAmount",
    "AllowanceTotalAmount",
    "ChargeTotalAmount",
    "PrepaidAmount",
    "PayableRoundingAmount",
    "PayableAmount",
];
const NONNEGATIVE: &[&[Name]] = &[
    &[a("AllowanceCharge"), b("Amount")],
    &[a("AllowanceCharge"), b("BaseAmount")],
    &[a("TaxTotal"), a("TaxSubtotal"), b("TaxAmount")],
    &[a("LegalMonetaryTotal"), b("LineExtensionAmount")],
    &[a("LegalMonetaryTotal"), b("TaxExclusiveAmount")],
    &[a("LegalMonetaryTotal"), b("TaxInclusiveAmount")],
    &[a("LegalMonetaryTotal"), b("AllowanceTotalAmount")],
    &[a("LegalMonetaryTotal"), b("ChargeTotalAmount")],
    &[a("LegalMonetaryTotal"), b("PrepaidAmount")],
    &[a("TaxTotal"), b("TaxAmount")],
    &[a("InvoiceLine"), a("AllowanceCharge"), b("Amount")],
    &[a("InvoiceLine"), a("AllowanceCharge"), b("BaseAmount")],
    &[a("InvoiceLine"), a("TaxTotal"), b("TaxAmount")],
    &[a("InvoiceLine"), a("Price"), b("PriceAmount")],
    &[
        a("InvoiceLine"),
        a("Price"),
        a("AllowanceCharge"),
        b("Amount"),
    ],
    &[
        a("InvoiceLine"),
        a("Price"),
        a("AllowanceCharge"),
        b("BaseAmount"),
    ],
    &[a("InvoiceLine"), b("InvoicedQuantity")],
    &[
        a("InvoiceLine"),
        a("TaxTotal"),
        a("TaxSubtotal"),
        b("TaxableAmount"),
    ],
    &[
        a("InvoiceLine"),
        a("TaxTotal"),
        a("TaxSubtotal"),
        b("TaxAmount"),
    ],
    &[a("TaxExchangeRate"), b("CalculationRate")],
];
