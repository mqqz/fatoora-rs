//! Remaining monetary predicates in the pinned KSA stylesheet (LGPL-3.0).
use super::{
    FailureKind,
    decimal::{ExactDecimal, FormattedNumber, parse_double, round_double},
    structural::indicator,
    xml::{CAC, NodeId, UBL, XmlView, a, b},
};
#[derive(Debug, Clone, Copy)]
pub(super) enum KsaArithmeticCheck {
    LineInclusive,
    ForeignTax,
    Adjustment,
    LineNet,
}
impl KsaArithmeticCheck {
    pub fn contexts(self, xml: &XmlView) -> Vec<NodeId> {
        match self {
            Self::LineInclusive => xml.all_path(&[a("InvoiceLine"), a("TaxTotal")]),
            Self::LineNet => xml.all(CAC, "InvoiceLine"),
            Self::ForeignTax => {
                if xml.is(0, UBL, "Invoice") {
                    vec![0]
                } else {
                    vec![]
                }
            }
            Self::Adjustment => {
                if !xml.is(0, UBL, "Invoice") {
                    return vec![];
                }
                let mut nodes = vec![];
                for path in [
                    vec![a("AllowanceCharge")],
                    vec![a("InvoiceLine"), a("AllowanceCharge")],
                ] {
                    let adjustments = xml.path(0, &path);
                    if adjustments
                        .iter()
                        .any(|&n| !xml.path(n, &[b("Amount")]).is_empty())
                    {
                        nodes.extend(
                            adjustments
                                .into_iter()
                                .filter(|&n| !xml.path(n, &[b("BaseAmount")]).is_empty()),
                        );
                    }
                }
                nodes.sort_unstable();
                nodes
            }
        }
    }
    pub fn passes(self, xml: &XmlView, node: NodeId, digits: usize) -> Result<bool, FailureKind> {
        use KsaArithmeticCheck::*;
        Ok(match self {
            LineInclusive => {
                let line = xml.node(node).parent.expect("tax total parent");
                let actual = double(xml, &xml.path(node, &[b("RoundingAmount")]))?;
                let tax = double(xml, &xml.path(node, &[b("TaxAmount")]))?;
                let net = double(xml, &xml.path(line, &[b("LineExtensionAmount")]))?;
                FormattedNumber::from_double(actual, digits)?
                    == FormattedNumber::from_double(
                        round_double((tax + net) * 100.0) / 100.0,
                        digits,
                    )?
            }
            ForeignTax => {
                let currencies = xml.path(node, &[b("DocumentCurrencyCode")]);
                if !currencies.iter().any(|&n| !xml.node(n).text.is_empty())
                    || !currencies.iter().any(|&n| xml.node(n).text != "SAR")
                {
                    return Ok(true);
                }
                let mut subtotals = vec![];
                let mut bare = vec![];
                for total in xml.path(node, &[a("TaxTotal")]) {
                    let dest = if xml.path(total, &[a("TaxSubtotal")]).is_empty() {
                        &mut bare
                    } else {
                        &mut subtotals
                    };
                    dest.extend(xml.path(total, &[b("TaxAmount")]));
                }
                if !positive(xml, &subtotals)? || !positive(xml, &bare)? {
                    return Ok(true);
                }
                round_double(double(xml, &subtotals)? * 100.0) / 100.0
                    != round_double(double(xml, &bare)? * 100.0) / 100.0
            }
            Adjustment => {
                let amount = xml.path(node, &[b("Amount")]);
                let base = xml.path(node, &[b("BaseAmount")]);
                if xml.singleton_text(&amount)?.unwrap_or("").is_empty()
                    || xml.singleton_text(&base)?.unwrap_or("").is_empty()
                {
                    return Ok(true);
                }
                let product = ((double(xml, &base)?
                    * double(xml, &xml.path(node, &[b("MultiplierFactorNumeric")]))?)
                    / 100.0)
                    * 100.0;
                FormattedNumber::from_double(double(xml, &amount)?, digits)?
                    == FormattedNumber::from_double((product + 0.5).floor() / 100.0, digits)?
            }
            LineNet => line_net(xml, node, digits)?,
        })
    }
}
fn double(xml: &XmlView, nodes: &[NodeId]) -> Result<f64, FailureKind> {
    xml.singleton_text(nodes)?
        .map_or(Ok(f64::NAN), parse_double)
}
fn positive(xml: &XmlView, nodes: &[NodeId]) -> Result<bool, FailureKind> {
    for &n in nodes {
        if parse_double(&xml.node(n).text)? > 0.0 {
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
        .map(|v| ExactDecimal::parse(v, digits))
        .transpose()
}
fn line_net(xml: &XmlView, line: NodeId, digits: usize) -> Result<bool, FailureKind> {
    let Some(net) = decimal(xml, &xml.path(line, &[b("LineExtensionAmount")]), digits)? else {
        return Ok(false);
    };
    let Some(quantity) = decimal(xml, &xml.path(line, &[b("InvoicedQuantity")]), digits)? else {
        return Ok(false);
    };
    let Some(price) = decimal(
        xml,
        &xml.path(line, &[a("Price"), b("PriceAmount")]),
        digits,
    )?
    else {
        return Ok(false);
    };
    let base = decimal(
        xml,
        &xml.path(line, &[a("Price"), b("BaseQuantity")]),
        digits,
    )?;
    let price = match base {
        Some(base) => price.divide_sdk(&base, digits)?,
        None => price,
    };
    let product = quantity
        .multiply(&price, digits)?
        .multiply(&ExactDecimal::from_i64(1000), digits)?
        .floor()
        .scale_down(1, digits)?
        .add(&ExactDecimal::parse("0.00000000001", digits)?, digits)?
        .scale_down(2, digits)?;
    let mut charges = ExactDecimal::zero();
    let mut allowances = ExactDecimal::zero();
    for adj in xml.path(line, &[a("AllowanceCharge")]) {
        for (is_charge, sum) in [(true, &mut charges), (false, &mut allowances)] {
            if indicator(xml, adj, is_charge)? {
                // The cast runs once per AllowanceCharge, requiring a singleton.
                if let Some(amount) = decimal(xml, &xml.path(adj, &[b("Amount")]), digits)? {
                    *sum = sum.add(&amount, digits)?;
                }
            }
        }
    }
    let expected = product
        .add(&charges, digits)?
        .subtract(&allowances, digits)?
        .round(2);
    let cent = ExactDecimal::parse("0.01", digits)?;
    Ok(net == expected
        || net == expected.add(&cent, digits)?
        || net == expected.subtract(&cent, digits)?)
}
