//! KSA adjustment and numeric-field predicates from the pinned SDK (LGPL-3.0).
use super::{
    FailureKind,
    decimal::{ExactDecimal, parse_double},
    identity::optional_length,
    structural::{has_transaction, indicator, scale},
    xml::{CAC, NodeId, UBL, XmlView, a, b, normalize_space},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum KsaAdjustmentCheck {
    AllowancePercentage,
    DocumentChargeReasonCode,
    DocumentChargeReason,
    DocumentChargeReasonLength,
    LineChargeReasonCode,
    LineChargeReason,
    LineChargeReasonLength,
    DocumentAllowanceReasonLength,
    LineOutsideRate,
    DocumentAllowanceOutsideRate,
    DocumentChargeOutsideRate,
    LineAllowanceReasonLength,
    BuyerOtherId,
    TaxPercentage,
    LineTaxScale,
    LineInclusiveScale,
    GrossNet,
}

impl KsaAdjustmentCheck {
    pub fn contexts(self, xml: &XmlView) -> Vec<NodeId> {
        use KsaAdjustmentCheck::*;
        match self {
            TaxPercentage => {
                let mut nodes =
                    xml.all_path(&[a("AllowanceCharge"), a("TaxCategory"), b("Percent")]);
                nodes.extend(xml.all_path(&[
                    a("TaxTotal"),
                    a("TaxSubtotal"),
                    a("TaxCategory"),
                    b("Percent"),
                ]));
                nodes.extend(xml.all_path(&[
                    a("InvoiceLine"),
                    a("Item"),
                    a("ClassifiedTaxCategory"),
                    b("Percent"),
                ]));
                nodes.sort_unstable();
                nodes.dedup();
                nodes
            }
            LineTaxScale | LineInclusiveScale => xml.all(CAC, "InvoiceLine"),
            GrossNet => xml.all_path(&[
                a("InvoiceLine"),
                a("Price"),
                a("AllowanceCharge"),
                b("BaseAmount"),
            ]),
            _ if !xml.is(0, UBL, "Invoice") => Vec::new(),
            AllowancePercentage => xml.all(CAC, "AllowanceCharge"),
            DocumentChargeReasonCode
            | DocumentChargeReason
            | DocumentChargeReasonLength
            | DocumentAllowanceReasonLength => xml.path(0, &[a("AllowanceCharge")]),
            LineChargeReasonCode
            | LineChargeReason
            | LineChargeReasonLength
            | LineAllowanceReasonLength => xml.path(0, &[a("InvoiceLine"), a("AllowanceCharge")]),
            LineOutsideRate => xml.path(
                0,
                &[a("InvoiceLine"), a("Item"), a("ClassifiedTaxCategory")],
            ),
            DocumentAllowanceOutsideRate | DocumentChargeOutsideRate => {
                xml.path(0, &[a("AllowanceCharge"), a("TaxCategory")])
            }
            BuyerOtherId => vec![0],
        }
    }

    pub fn passes(self, xml: &XmlView, node: NodeId, digits: usize) -> Result<bool, FailureKind> {
        use KsaAdjustmentCheck::*;
        match self {
            AllowancePercentage => {
                if xml
                    .node(node)
                    .parent
                    .is_some_and(|id| xml.is(id, CAC, "Price"))
                    || !indicator(xml, node, false)?
                {
                    return Ok(true);
                }
                let nodes = xml.path(node, &[b("MultiplierFactorNumeric")]);
                let value = xml.singleton_text(&nodes)?.unwrap_or("");
                // This guard uses raw string-length; whitespace must still be
                // cast, unlike the normalized-empty guard on TaxPercentage.
                if value.is_empty() {
                    return Ok(true);
                }
                percentage(xml, &nodes, value, digits)
            }
            DocumentChargeReasonCode
            | DocumentChargeReason
            | DocumentChargeReasonLength
            | LineChargeReasonCode
            | LineChargeReason
            | LineChargeReasonLength
            | DocumentAllowanceReasonLength
            | LineAllowanceReasonLength => {
                let charge = !matches!(
                    self,
                    DocumentAllowanceReasonLength | LineAllowanceReasonLength
                );
                if !indicator(xml, node, charge)? {
                    return Ok(true);
                }
                let field = if matches!(self, DocumentChargeReasonCode | LineChargeReasonCode) {
                    "AllowanceChargeReasonCode"
                } else {
                    "AllowanceChargeReason"
                };
                let nodes = xml.path(node, &[b(field)]);
                if matches!(
                    self,
                    DocumentChargeReasonLength
                        | LineChargeReasonLength
                        | DocumentAllowanceReasonLength
                        | LineAllowanceReasonLength
                ) {
                    optional_length(xml, &nodes, 1, 1000)
                } else {
                    Ok(!normalize_space(xml.singleton_text(&nodes)?.unwrap_or("")).is_empty())
                }
            }
            LineOutsideRate | DocumentAllowanceOutsideRate | DocumentChargeOutsideRate => {
                if !matches!(self, LineOutsideRate) {
                    let adjustment = xml.node(node).parent.expect("selected adjustment category");
                    if !indicator(xml, adjustment, matches!(self, DocumentChargeOutsideRate))? {
                        return Ok(true);
                    }
                }
                if normalize_space(
                    xml.singleton_text(&xml.path(node, &[b("ID")]))?
                        .unwrap_or(""),
                ) != "O"
                {
                    return Ok(true);
                }
                // General comparisons cast each untyped value to double. No
                // TaxScheme='VAT' gate exists in these source predicates.
                for percent in xml.path(node, &[b("Percent")]) {
                    let value = parse_double(&xml.node(percent).text)?;
                    // NaN satisfies neither comparison in the source.
                    if !value.is_nan() && value != 0.0 {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            BuyerOtherId => {
                if !has_transaction(xml, "01")
                    || !xml
                        .path(
                            node,
                            &[
                                a("AccountingCustomerParty"),
                                a("Party"),
                                a("PartyTaxScheme"),
                                b("CompanyID"),
                            ],
                        )
                        .is_empty()
                {
                    return Ok(true);
                }
                let ids = xml.path(
                    node,
                    &[
                        a("AccountingCustomerParty"),
                        a("Party"),
                        a("PartyIdentification"),
                        b("ID"),
                    ],
                );
                Ok(!normalize_space(xml.singleton_text(&ids)?.unwrap_or("")).is_empty())
            }
            TaxPercentage => {
                let value = &xml.node(node).text;
                if normalize_space(value).is_empty() {
                    return Ok(true);
                }
                // Keep the source's operand order: contains('%', value).
                Ok(percentage(xml, &[node], value, digits)? && !"%".contains(value))
            }
            LineTaxScale | LineInclusiveScale => scale(
                xml,
                &xml.path(
                    node,
                    &[
                        a("TaxTotal"),
                        b(if matches!(self, LineTaxScale) {
                            "TaxAmount"
                        } else {
                            "RoundingAmount"
                        }),
                    ],
                ),
            ),
            GrossNet => {
                let adjustment = xml
                    .node(node)
                    .parent
                    .expect("selected base amount has parent");
                let price = xml
                    .node(adjustment)
                    .parent
                    .expect("selected allowance has price parent");
                let net = decimal(xml, &xml.path(price, &[b("PriceAmount")]), digits)?;
                let base = ExactDecimal::parse(&xml.node(node).text, digits)?;
                let discount = decimal(xml, &xml.path(adjustment, &[b("Amount")]), digits)?;
                Ok(match (net, discount) {
                    (Some(net), Some(discount)) => net == base.subtract(&discount, digits)?,
                    _ => false,
                })
            }
        }
    }
}

fn percentage(
    xml: &XmlView,
    nodes: &[NodeId],
    value: &str,
    digits: usize,
) -> Result<bool, FailureKind> {
    let value = ExactDecimal::parse(value, digits)?;
    Ok(value >= ExactDecimal::zero() && value <= ExactDecimal::from_i64(100) && scale(xml, nodes)?)
}
fn decimal(
    xml: &XmlView,
    nodes: &[NodeId],
    digits: usize,
) -> Result<Option<ExactDecimal>, FailureKind> {
    xml.singleton_text(nodes)?
        .map(|text| ExactDecimal::parse(text, digits))
        .transpose()
}
