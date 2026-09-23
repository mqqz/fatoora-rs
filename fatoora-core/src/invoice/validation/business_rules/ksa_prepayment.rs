//! Prepayment predicates from the pinned ZATCA SDK profile (LGPL-3.0).
use super::{
    FailureKind,
    decimal::{ExactDecimal, FormattedNumber, parse_double, round_double},
    structural::{is_vat, scale},
    xml::{NodeId, UBL, XmlView, a, b, normalize_space},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum KsaPrepaymentCheck {
    Total,
    InactiveZeroTax,
    InactiveStandardTax,
    DocumentType,
    ZeroLineAmounts,
    ZeroAdjustments,
    ReferenceFields,
    MissingReferences,
    SubtotalFields,
    ActiveZeroTax,
    ActiveStandardTax,
    AmountScale,
    ZeroRate,
    ExemptRate,
    OutsideRate,
}

impl KsaPrepaymentCheck {
    pub fn contexts(self, xml: &XmlView) -> Result<Vec<NodeId>, FailureKind> {
        use KsaPrepaymentCheck::*;
        if matches!(self, Total) {
            return Ok(if xml.is_document_root(0) {
                vec![0]
            } else {
                vec![]
            });
        }
        if !xml.is(0, UBL, "Invoice") {
            return Ok(Vec::new());
        }
        let active = any_double(
            xml,
            &xml.path(0, &[a("LegalMonetaryTotal"), b("PrepaidAmount")]),
            |n| n > 0.0,
        )?;
        if active == matches!(self, InactiveZeroTax | InactiveStandardTax) {
            return Ok(Vec::new());
        }
        Ok(match self {
            Total => unreachable!(),
            DocumentType | ZeroLineAmounts | ZeroAdjustments | ReferenceFields | SubtotalFields => {
                xml.path(0, &[a("InvoiceLine"), a("DocumentReference")])
            }
            MissingReferences => {
                if xml
                    .path(0, &[a("InvoiceLine"), a("DocumentReference")])
                    .is_empty()
                {
                    xml.path(0, &[a("InvoiceLine")])
                } else {
                    Vec::new()
                }
            }
            _ => xml.path(0, &[a("InvoiceLine"), a("TaxTotal"), a("TaxSubtotal")]),
        })
    }

    pub fn passes(self, xml: &XmlView, node: NodeId, digits: usize) -> Result<bool, FailureKind> {
        use KsaPrepaymentCheck::*;
        match self {
            Total => total(xml, digits),
            InactiveZeroTax | ActiveZeroTax => {
                if !zero_branch(xml, node)? {
                    return Ok(true);
                }
                zero_tax(xml, node, digits)
            }
            InactiveStandardTax | ActiveStandardTax => {
                if zero_branch(xml, node)? {
                    return Ok(true);
                }
                standard_tax(xml, node, digits)
            }
            DocumentType => {
                let codes = xml.path(node, &[b("DocumentTypeCode")]);
                if !codes.iter().any(|id| xml.node(*id).text != "386") {
                    return Ok(true);
                }
                Ok(normalize_space(xml.singleton_text(&codes)?.unwrap_or("")) == "386")
            }
            ZeroLineAmounts | ZeroAdjustments => {
                // The source's otherwise branch includes an absent type code;
                // whitespace around 386 takes the preceding branch instead.
                if xml
                    .path(node, &[b("DocumentTypeCode")])
                    .iter()
                    .any(|id| xml.node(*id).text != "386")
                {
                    return Ok(true);
                }
                let line = xml.node(node).parent.expect("selected document reference");
                if matches!(self, ZeroAdjustments) {
                    return Ok(xml.path(line, &[a("AllowanceCharge")]).is_empty()
                        || any_double(
                            xml,
                            &xml.path(line, &[a("AllowanceCharge"), b("Amount")]),
                            |n| n == 0.0,
                        )?);
                }
                for path in [
                    vec![b("LineExtensionAmount")],
                    vec![a("TaxTotal"), b("TaxAmount")],
                    vec![a("TaxTotal"), b("RoundingAmount")],
                    vec![a("Price"), b("PriceAmount")],
                ] {
                    if !any_double(xml, &xml.path(line, &path), |n| n == 0.0)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            ReferenceFields => Ok(["ID", "IssueDate", "IssueTime", "DocumentTypeCode"]
                .iter()
                .all(|field| !xml.path(node, &[b(field)]).is_empty())),
            MissingReferences => Ok(false),
            SubtotalFields => {
                let line = xml.node(node).parent.expect("selected document reference");
                Ok([
                    vec![b("TaxAmount")],
                    vec![a("TaxCategory"), b("Percent")],
                    vec![b("TaxableAmount")],
                    vec![a("TaxCategory"), b("ID")],
                ]
                .iter()
                .all(|tail| {
                    let mut path = vec![a("TaxTotal"), a("TaxSubtotal")];
                    path.extend(tail);
                    !xml.path(line, &path).is_empty()
                }))
            }
            AmountScale => Ok(scale(xml, &xml.path(node, &[b("TaxableAmount")]))?
                && scale(xml, &xml.path(node, &[b("TaxAmount")]))?),
            ZeroRate | ExemptRate | OutsideRate => {
                let code = match self {
                    ZeroRate => "Z",
                    ExemptRate => "E",
                    _ => "O",
                };
                for category in xml.path(node, &[a("TaxCategory")]) {
                    if category_code(xml, category)? == code && is_vat(xml, category)? {
                        // The cast intentionally uses every category's rate,
                        // rather than only the category satisfying the guard.
                        return Ok(decimal(
                            xml,
                            &xml.path(node, &[a("TaxCategory"), b("Percent")]),
                            digits,
                        )? == Some(ExactDecimal::zero()));
                    }
                }
                Ok(true)
            }
        }
    }
}

fn total(xml: &XmlView, digits: usize) -> Result<bool, FailureKind> {
    // All variables are absolute Invoice paths even on the CreditNote context.
    if !xml.is(0, UBL, "Invoice") {
        return Ok(true);
    }
    let prepaid_nodes = xml.path(0, &[a("LegalMonetaryTotal"), b("PrepaidAmount")]);
    let prepaid = decimal(xml, &prepaid_nodes, digits)?.unwrap_or_else(ExactDecimal::zero);
    let taxable = xml.path(
        0,
        &[
            a("InvoiceLine"),
            a("TaxTotal"),
            a("TaxSubtotal"),
            b("TaxableAmount"),
        ],
    );
    let tax = xml.path(
        0,
        &[
            a("InvoiceLine"),
            a("TaxTotal"),
            a("TaxSubtotal"),
            b("TaxAmount"),
        ],
    );
    if prepaid == ExactDecimal::zero() && (!taxable.is_empty() || !tax.is_empty()) {
        return Ok(false);
    }
    let taxable_sum = sum_double(xml, &taxable)?;
    let tax_sum = sum_double(xml, &tax)?;
    if prepaid != ExactDecimal::zero()
        && taxable_sum > 0.0
        && tax_sum > 0.0
        && xml
            .path(
                0,
                &[
                    a("InvoiceLine"),
                    a("DocumentReference"),
                    b("DocumentTypeCode"),
                ],
            )
            .iter()
            .any(|id| xml.node(*id).text != "386")
    {
        return Ok(false);
    }
    Ok(FormattedNumber::from_decimal(&prepaid)
        == FormattedNumber::from_double(taxable_sum + tax_sum, digits)?)
}

fn category_code(xml: &XmlView, category: NodeId) -> Result<String, FailureKind> {
    Ok(normalize_space(
        xml.singleton_text(&xml.path(category, &[b("ID")]))?
            .unwrap_or(""),
    ))
}

fn zero_branch(xml: &XmlView, subtotal: NodeId) -> Result<bool, FailureKind> {
    let mut codes = Vec::new();
    for category in xml.path(subtotal, &[a("TaxCategory")]) {
        let code = category_code(xml, category)?;
        if code == "S" {
            return Ok(false);
        }
        codes.push(code);
    }
    let percent = xml.path(subtotal, &[a("TaxCategory"), b("Percent")]);
    Ok((codes.iter().any(|code| code == "O") && percent.is_empty())
        || codes.iter().any(|code| matches!(code.as_str(), "E" | "Z"))
        || normalize_space(xml.singleton_text(&percent)?.unwrap_or("")).is_empty())
}

fn zero_tax(xml: &XmlView, subtotal: NodeId, digits: usize) -> Result<bool, FailureKind> {
    let actual = formatted_double(xml, &xml.path(subtotal, &[b("TaxAmount")]), digits)?;
    let taxable = decimal(xml, &xml.path(subtotal, &[b("TaxableAmount")]), digits)?;
    // The first expression multiplies a present taxable amount by literal zero.
    // Empty arithmetic stays empty, and format-number(()) produces "NaN".
    let zero = taxable.as_ref().map_or(FormattedNumber::NaN, |_| {
        FormattedNumber::from_decimal(&ExactDecimal::zero())
    });
    if actual != zero {
        return Ok(false);
    }
    let rate = decimal(
        xml,
        &xml.path(subtotal, &[a("TaxCategory"), b("Percent")]),
        digits,
    )?;
    let expected = match (taxable, rate) {
        (Some(taxable), Some(rate)) => FormattedNumber::from_decimal(
            &taxable
                .multiply(&rate, digits)?
                .scale_down(2, digits)?
                .round(2),
        ),
        _ => FormattedNumber::NaN,
    };
    Ok(actual == expected)
}

fn standard_tax(xml: &XmlView, subtotal: NodeId, digits: usize) -> Result<bool, FailureKind> {
    let all_rates = xml.path(subtotal, &[a("TaxCategory"), b("Percent")]);
    if normalize_space(xml.singleton_text(&all_rates)?.unwrap_or("")).is_empty() {
        return Ok(false);
    }
    let actual = formatted_double(xml, &xml.path(subtotal, &[b("TaxAmount")]), digits)?;
    let taxable = optional_double(xml, &xml.path(subtotal, &[b("TaxableAmount")]))?;
    let mut rates = Vec::new();
    for category in xml.path(subtotal, &[a("TaxCategory")]) {
        if is_vat(xml, category)?
            && let Some(rate) = decimal(xml, &xml.path(category, &[b("Percent")]), digits)?
        {
            rates.push(rate);
        }
    }
    if rates.len() > 1 {
        return Err(FailureKind::Cardinality);
    }
    let Some((taxable, rate)) = taxable.zip(rates.first()) else {
        return Ok(actual == FormattedNumber::NaN);
    };
    // TaxableAmount remains untyped, promoting this complete expression to
    // double despite the explicit decimal cast of the VAT rate.
    let expected = round_double(((taxable * rate.to_double()) / 100.0) * 100.0 + 0.01) / 100.0;
    for candidate in [expected - 0.01, expected + 0.01, expected] {
        if actual == FormattedNumber::from_double(candidate, digits)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn decimal(
    xml: &XmlView,
    nodes: &[NodeId],
    digits: usize,
) -> Result<Option<ExactDecimal>, FailureKind> {
    xml.singleton_text(nodes)?
        .map(|value| ExactDecimal::parse(value, digits))
        .transpose()
}

fn optional_double(xml: &XmlView, nodes: &[NodeId]) -> Result<Option<f64>, FailureKind> {
    xml.singleton_text(nodes)?.map(parse_double).transpose()
}

fn formatted_double(
    xml: &XmlView,
    nodes: &[NodeId],
    digits: usize,
) -> Result<FormattedNumber, FailureKind> {
    optional_double(xml, nodes)?.map_or(Ok(FormattedNumber::NaN), |value| {
        FormattedNumber::from_double(value, digits)
    })
}

fn any_double(
    xml: &XmlView,
    nodes: &[NodeId],
    predicate: impl Fn(f64) -> bool,
) -> Result<bool, FailureKind> {
    for node in nodes {
        if predicate(parse_double(&xml.node(*node).text)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sum_double(xml: &XmlView, nodes: &[NodeId]) -> Result<f64, FailureKind> {
    let Some((first, rest)) = nodes.split_first() else {
        return Ok(0.0);
    };
    // The empty-sequence fallback is not an extra operand: adding positive
    // zero before the first amount would erase a sole negative zero.
    let first = parse_double(&xml.node(*first).text)?;
    rest.iter().try_fold(first, |sum, node| {
        Ok(sum + parse_double(&xml.node(*node).text)?)
    })
}
