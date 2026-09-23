//! Remaining legal monetary reconciliation from the pinned CEN profile.
//! Translated predicates retain LGPL-3.0; see the source-site metadata.
use super::{
    FailureKind,
    decimal::{ExactDecimal, parse_double},
    structural::indicator,
    xml::{CAC, NodeId, UBL, XmlView, a, b, normalize_space},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum TotalsCheck {
    AllowanceSum,
    EmptyChargeSum,
    ChargeSum,
    EmptyChargeExclusive,
    Exclusive,
    Payable,
}

impl TotalsCheck {
    pub fn contexts(self, xml: &XmlView) -> Vec<NodeId> {
        xml.all(CAC, "LegalMonetaryTotal")
    }
    pub fn passes(
        self,
        xml: &XmlView,
        node: NodeId,
        digits: usize,
        line_sum: &std::cell::OnceCell<Result<ExactDecimal, FailureKind>>,
    ) -> Result<bool, FailureKind> {
        let amount = |field: &'static str| decimal(xml, &xml.path(node, &[b(field)]), digits);
        let empty_charge = || {
            let nodes = xml.path(node, &[b("ChargeTotalAmount")]);
            Ok::<_, FailureKind>(
                xml.singleton_text(&nodes)?
                    .is_some_and(|s| normalize_space(s).is_empty()),
            )
        };
        match self {
            Self::EmptyChargeSum | Self::EmptyChargeExclusive => Ok(!empty_charge()?),
            Self::AllowanceSum | Self::ChargeSum => {
                let charge = matches!(self, Self::ChargeSum);
                if charge && empty_charge()? {
                    return Ok(true);
                }
                let mut sum = ExactDecimal::zero();
                let mut count = 0;
                if let Some(parent) = xml.node(node).parent {
                    for adjustment in xml.path(parent, &[a("AllowanceCharge")]) {
                        if indicator(xml, adjustment, charge)? {
                            count += 1;
                            if let Some(value) =
                                decimal(xml, &xml.path(adjustment, &[b("Amount")]), digits)?
                            {
                                sum = sum.add(&value, digits)?;
                            }
                        }
                    }
                }
                let actual = amount(if charge {
                    "ChargeTotalAmount"
                } else {
                    "AllowanceTotalAmount"
                })?;
                Ok(match actual {
                    Some(value) => value == sum.round(2),
                    None => count == 0,
                })
            }
            Self::Exclusive => {
                if empty_charge()? {
                    return Ok(true);
                }
                let exclusive = amount("TaxExclusiveAmount")?;
                let charge = amount("ChargeTotalAmount")?;
                let allowance = amount("AllowanceTotalAmount")?;
                let expected = if charge.is_none() && allowance.is_none() {
                    amount("LineExtensionAmount")?
                } else {
                    // The source calls xs:decimal(sum(raw node sequence)). Raw
                    // untyped values promote to double, unlike BR-CO-10's
                    // explicit decimal conversion of each individual line.
                    let mut sum = line_sum
                        .get_or_init(|| {
                            let mut sum = 0.0;
                            if xml.is(0, UBL, "Invoice") {
                                for id in xml.path(0, &[a("InvoiceLine"), b("LineExtensionAmount")])
                                {
                                    sum += parse_double(&xml.node(id).text)?;
                                }
                            }
                            ExactDecimal::from_double(sum, digits)
                        })
                        .as_ref()
                        .map_err(Clone::clone)?
                        .clone();
                    if let Some(charge) = charge {
                        sum = sum.add(&charge, digits)?;
                    }
                    if let Some(allowance) = allowance {
                        sum = sum.subtract(&allowance, digits)?;
                    }
                    Some(sum.round(2))
                };
                Ok(matches!((exclusive, expected), (Some(a), Some(b)) if a == b))
            }
            Self::Payable => {
                let payable = amount("PayableAmount")?;
                let inclusive = amount("TaxInclusiveAmount")?;
                let prepaid = amount("PrepaidAmount")?;
                let rounding = amount("PayableRoundingAmount")?;
                let (Some(payable), Some(inclusive)) = (payable, inclusive) else {
                    return Ok(false);
                };
                Ok(match (prepaid, rounding) {
                    (None, None) => payable == inclusive,
                    (Some(prepaid), None) => {
                        payable == inclusive.subtract(&prepaid, digits)?.round(2)
                    }
                    (None, Some(rounding)) => {
                        payable.subtract(&rounding, digits)?.round(2) == inclusive
                    }
                    (Some(prepaid), Some(rounding)) => {
                        payable.subtract(&rounding, digits)?.round(2)
                            == inclusive.subtract(&prepaid, digits)?.round(2)
                    }
                })
            }
        }
    }
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
