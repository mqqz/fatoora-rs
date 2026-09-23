//! VAT category predicates translated from the pinned CEN profile (LGPL-3.0).
//! Native paths preserve each source expression's category and numeric scope.
use super::{
    FailureKind,
    decimal::{ExactDecimal, parse_double, round_double},
    structural::{indicator, is_vat},
    xml::{CAC, NodeId, UBL, XmlView, a, b, normalize_space},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum VatCheck {
    ExemptBreakdown,
    OutsideBreakdown,
    StandardBreakdown,
    ZeroChargeRate,
    ExemptChargeRate,
    ZeroBreakdown,
    TaxComputation,
    ExemptTaxable,
    ExemptTaxZero,
    ExemptAllowanceRate,
    ExemptItemRate,
    OutsideTaxable,
    OutsideTaxZero,
    StandardTaxable,
    StandardTaxComputation,
    StandardNoExemption,
    StandardAllowanceRate,
    StandardChargeRate,
    ZeroTaxable,
    ZeroTaxZero,
    ZeroAllowanceRate,
    ZeroItemRate,
    StandardItemRate,
}

impl VatCheck {
    pub fn contexts(self, xml: &XmlView) -> Vec<NodeId> {
        use VatCheck::*;
        match self {
            TaxComputation => {
                if xml.is(0, UBL, "Invoice") {
                    xml.path(0, &[a("TaxTotal"), a("TaxSubtotal")])
                } else {
                    Vec::new()
                }
            }
            ExemptBreakdown | OutsideBreakdown | StandardBreakdown | ZeroBreakdown
            | ZeroChargeRate | ExemptChargeRate => {
                if xml.is_document_root(0) {
                    vec![0]
                } else {
                    Vec::new()
                }
            }
            ExemptAllowanceRate
            | StandardAllowanceRate
            | StandardChargeRate
            | ZeroAllowanceRate => xml.all_path(&[a("AllowanceCharge"), a("TaxCategory")]),
            ExemptItemRate | ZeroItemRate | StandardItemRate => {
                let mut nodes =
                    xml.all_path(&[a("InvoiceLine"), a("Item"), a("ClassifiedTaxCategory")]);
                if !matches!(self, StandardItemRate) {
                    nodes.extend(xml.all_path(&[
                        a("CreditNoteLine"),
                        a("Item"),
                        a("ClassifiedTaxCategory"),
                    ]));
                    nodes.sort_unstable();
                }
                nodes
            }
            _ => xml.path(0, &[a("TaxTotal"), a("TaxSubtotal"), a("TaxCategory")]),
        }
    }

    pub fn passes(self, xml: &XmlView, node: NodeId, digits: usize) -> Result<bool, FailureKind> {
        use VatCheck::*;
        let code = match self {
            ExemptBreakdown | ExemptChargeRate | ExemptTaxable | ExemptTaxZero
            | ExemptAllowanceRate | ExemptItemRate => "E",
            OutsideBreakdown | OutsideTaxable | OutsideTaxZero => "O",
            StandardBreakdown
            | StandardTaxable
            | StandardTaxComputation
            | StandardNoExemption
            | StandardAllowanceRate
            | StandardChargeRate
            | StandardItemRate => "S",
            ZeroChargeRate | ZeroBreakdown | ZeroTaxable | ZeroTaxZero | ZeroAllowanceRate
            | ZeroItemRate => "Z",
            TaxComputation => "",
        };
        match self {
            TaxComputation => tax_computation(xml, node, digits),
            StandardTaxComputation => {
                if !category_matches(xml, node, code)? {
                    return Ok(true);
                }
                let rate = xml
                    .singleton_text(&xml.path(node, &[b("Percent")]))?
                    .unwrap_or("");
                if normalize_space(rate).is_empty() {
                    return Ok(false);
                }
                let subtotal = xml.node(node).parent.expect("selected tax category");
                tax_computation(xml, subtotal, digits)
            }
            ExemptBreakdown | OutsideBreakdown | StandardBreakdown | ZeroBreakdown => {
                let mut sources = xml.all_path(&[a("AllowanceCharge"), a("TaxCategory")]);
                sources.extend(xml.all(CAC, "ClassifiedTaxCategory"));
                if !has_vat_id(xml, &sources, code)? {
                    return Ok(true);
                }
                has_vat_id(
                    xml,
                    &xml.path(node, &[a("TaxTotal"), a("TaxSubtotal"), a("TaxCategory")]),
                    code,
                )
            }
            ZeroChargeRate | ExemptChargeRate => {
                let mut applies = false;
                for adjustment in xml.path(node, &[a("AllowanceCharge")]) {
                    if indicator(xml, adjustment, true)? {
                        for category in xml.path(adjustment, &[a("TaxCategory")]) {
                            if category_matches(xml, category, code)? {
                                applies = true;
                                break;
                            }
                        }
                    }
                }
                if !applies {
                    return Ok(true);
                }
                // This absolute source operand intentionally includes every
                // document allowance/charge category, irrespective of code.
                let rates = if xml.is(0, UBL, "Invoice") {
                    xml.path(0, &[a("AllowanceCharge"), a("TaxCategory"), b("Percent")])
                } else {
                    Vec::new()
                };
                any_double(xml, &rates, |value| value == 0.0)
            }
            ExemptAllowanceRate
            | StandardAllowanceRate
            | StandardChargeRate
            | ZeroAllowanceRate => {
                let adjustment = xml.node(node).parent.expect("selected allowance category");
                let selected = if matches!(self, StandardAllowanceRate) {
                    // The later charge template wins its same-pattern,
                    // same-priority tie when both indicators occur.
                    !indicator(xml, adjustment, true)? && indicator(xml, adjustment, false)?
                } else {
                    indicator(xml, adjustment, matches!(self, StandardChargeRate))?
                };
                if !selected || !category_matches(xml, node, code)? {
                    return Ok(true);
                }
                rate_passes(xml, node, code, digits)
            }
            ExemptItemRate | ZeroItemRate | StandardItemRate => {
                if !category_matches(xml, node, code)? {
                    return Ok(true);
                }
                rate_passes(xml, node, code, digits)
            }
            ExemptTaxable | OutsideTaxable | StandardTaxable | ZeroTaxable => {
                if !category_matches(xml, node, code)? {
                    return Ok(true);
                }
                taxable_passes(xml, node, code, digits)
            }
            ExemptTaxZero | OutsideTaxZero | ZeroTaxZero => {
                if !category_matches(xml, node, code)? {
                    return Ok(true);
                }
                let subtotal = xml.node(node).parent.expect("selected tax category");
                Ok(amount(xml, subtotal, "TaxAmount", digits)? == Some(ExactDecimal::zero()))
            }
            StandardNoExemption => {
                if !category_matches(xml, node, code)? {
                    return Ok(true);
                }
                let global_standard_text = xml
                    .path(
                        0,
                        &[a("TaxTotal"), a("TaxSubtotal"), a("TaxCategory"), b("ID")],
                    )
                    .into_iter()
                    .any(|id| xml.node(id).direct_text.iter().any(|text| text == "S"));
                Ok(!global_standard_text
                    || (xml.path(node, &[b("TaxExemptionReason")]).is_empty()
                        && xml.path(node, &[b("TaxExemptionReasonCode")]).is_empty()))
            }
        }
    }
}

fn code_matches(xml: &XmlView, category: NodeId, code: &str) -> Result<bool, FailureKind> {
    Ok(normalize_space(
        xml.singleton_text(&xml.path(category, &[b("ID")]))?
            .unwrap_or(""),
    ) == code)
}

fn category_matches(xml: &XmlView, category: NodeId, code: &str) -> Result<bool, FailureKind> {
    Ok(code_matches(xml, category, code)? && is_vat(xml, category)?)
}

/// Presence predicates filter each ID node independently. Unlike matching a
/// category with normalize-space(cbc:ID), repeated IDs are not a scalar error.
fn has_vat_id(xml: &XmlView, categories: &[NodeId], code: &str) -> Result<bool, FailureKind> {
    for &category in categories {
        if is_vat(xml, category)?
            && xml
                .path(category, &[b("ID")])
                .into_iter()
                .any(|id| normalize_space(&xml.node(id).text) == code)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn has_code(xml: &XmlView, categories: &[NodeId], code: &str) -> Result<bool, FailureKind> {
    for &category in categories {
        if code_matches(xml, category, code)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn any_double(
    xml: &XmlView,
    nodes: &[NodeId],
    test: impl Fn(f64) -> bool,
) -> Result<bool, FailureKind> {
    for &node in nodes {
        if test(parse_double(&xml.node(node).text)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn amount(
    xml: &XmlView,
    node: NodeId,
    field: &'static str,
    digits: usize,
) -> Result<Option<ExactDecimal>, FailureKind> {
    xml.singleton_text(&xml.path(node, &[b(field)]))?
        .map(|text| ExactDecimal::parse(text, digits))
        .transpose()
}

fn rate_passes(
    xml: &XmlView,
    node: NodeId,
    code: &str,
    digits: usize,
) -> Result<bool, FailureKind> {
    if code == "S" {
        any_double(xml, &xml.path(node, &[b("Percent")]), |value| value > 0.0)
    } else {
        Ok(amount(xml, node, "Percent", digits)? == Some(ExactDecimal::zero()))
    }
}

fn taxable_passes(
    xml: &XmlView,
    category: NodeId,
    code: &str,
    digits: usize,
) -> Result<bool, FailureKind> {
    let subtotal = xml.node(category).parent.expect("selected tax category");
    let total = xml.node(subtotal).parent.expect("selected tax subtotal");
    let document = xml.node(total).parent.expect("selected tax total");
    let mut sources = xml.path(document, &[a("AllowanceCharge"), a("TaxCategory")]);
    sources.extend(xml.path(
        document,
        &[a("InvoiceLine"), a("Item"), a("ClassifiedTaxCategory")],
    ));
    if !has_vat_id(xml, &sources, code)? {
        return Ok(false);
    }
    let mut expected = ExactDecimal::zero();
    for line in xml.path(document, &[a("InvoiceLine")]) {
        // The arithmetic filters intentionally omit TaxScheme. VAT association
        // is required only by the separate source-existence guard above.
        if has_code(
            xml,
            &xml.path(line, &[a("Item"), a("ClassifiedTaxCategory")]),
            code,
        )? && let Some(value) = amount(xml, line, "LineExtensionAmount", digits)?
        {
            expected = expected.add(&value, digits)?;
        }
    }
    for charge in [true, false] {
        let mut sum = ExactDecimal::zero();
        for adjustment in xml.path(document, &[a("AllowanceCharge")]) {
            if indicator(xml, adjustment, charge)?
                && has_code(xml, &xml.path(adjustment, &[a("TaxCategory")]), code)?
                && let Some(value) = amount(xml, adjustment, "Amount", digits)?
            {
                sum = sum.add(&value, digits)?;
            }
        }
        expected = if charge {
            expected.add(&sum, digits)?
        } else {
            expected.subtract(&sum, digits)?
        };
    }
    if code == "S" {
        // BR-S-08 reconciles the sum of matching subtotals in this TaxTotal,
        // rather than this category's own taxable amount or rate grouping.
        let mut actual = ExactDecimal::zero();
        for sibling in xml.path(total, &[a("TaxSubtotal")]) {
            if has_code(xml, &xml.path(sibling, &[a("TaxCategory")]), code)?
                && let Some(value) = amount(xml, sibling, "TaxableAmount", digits)?
            {
                actual = actual.add(&value, digits)?;
            }
        }
        Ok(actual == expected)
    } else {
        Ok(amount(xml, subtotal, "TaxableAmount", digits)? == Some(expected))
    }
}

fn double(xml: &XmlView, nodes: &[NodeId]) -> Result<Option<f64>, FailureKind> {
    xml.singleton_text(nodes)?.map(parse_double).transpose()
}

fn tax_computation(xml: &XmlView, subtotal: NodeId, digits: usize) -> Result<bool, FailureKind> {
    let tax = double(xml, &xml.path(subtotal, &[b("TaxAmount")]))?;
    let taxable = double(xml, &xml.path(subtotal, &[b("TaxableAmount")]))?;
    let mut rates = Vec::new();
    for category in xml.path(subtotal, &[a("TaxCategory")]) {
        if is_vat(xml, category)? {
            rates.extend(xml.path(category, &[b("Percent")]));
        }
    }
    let rate = double(xml, &rates)?;
    let product = match (taxable, rate) {
        (Some(taxable), Some(rate)) => taxable * (rate / 100.0),
        _ => f64::NAN,
    };
    let formatted = if product.is_nan() {
        f64::NAN
    } else if product.is_infinite() {
        // The default format-number infinity-symbol is "Infinity", which the
        // following xs:double cast cannot parse (its spelling is "INF").
        return Err(FailureKind::InvalidDouble);
    } else {
        // XSLT 2.0 §16.4.3 chooses a shortest round-tripping decimal, then
        // rounds half-even. SDK probes distinguish 2.675 -> 2.68 from direct
        // binary rounding and cover the adjacent doubles on either side.
        // https://www.w3.org/TR/2007/REC-xslt20-20070123/#format-number
        ExactDecimal::parse(&product.to_string(), digits)?
            .round_half_even(2)
            .to_double()
    };
    let should_be = round_double(formatted * 100.0) / 100.0;
    // The source declares this decimal expression as xs:float. Preserve that
    // single-precision rounding before promotion back to double arithmetic.
    let tolerance = ((xml.all(CAC, "InvoiceLine").len() as f64 / 100.0) as f32) as f64;
    let upper = round_double((should_be + tolerance) * 100.0) / 100.0;
    let lower = round_double((should_be - tolerance) * 100.0) / 100.0;
    Ok(tax.is_some_and(|tax| (tax <= upper && tax >= lower) || tax == should_be))
}
