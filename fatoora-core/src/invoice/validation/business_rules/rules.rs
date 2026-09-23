//! Native translations of the selected SDK predicates. See metadata.rs and the
//! pinned catalog for exact source sites. Upstream expressions retain their
//! recorded LGPL-3.0 terms; see THIRD_PARTY_NOTICES.md.
use super::{
    FailureKind,
    decimal::ExactDecimal,
    xml::{CAC, CBC, NodeId, UBL, XmlView, normalize_space},
};
use std::cell::OnceCell;

#[derive(Debug, Clone, Copy)]
pub(super) enum Check {
    Identity(super::identity::IdentityCheck),
    LineSum,
    TotalScale(&'static str),
    InclusiveTotal,
    ItemName,
    LineAllowanceScale(&'static str),
    TaxSum,
    TaxScale(&'static str),
    TaxCurrency,
    BareTaxTotal,
}

pub(super) struct Facts<'a> {
    xml: &'a XmlView,
    digits: usize,
    line_sum: OnceCell<Result<ExactDecimal, FailureKind>>,
    subtotal_sum: OnceCell<Result<ExactDecimal, FailureKind>>,
    document_currencies: Vec<NodeId>,
    tax_currencies: Vec<NodeId>,
}

impl<'a> Facts<'a> {
    pub fn new(xml: &'a XmlView, digits: usize) -> Self {
        Self {
            xml,
            digits,
            line_sum: OnceCell::new(),
            subtotal_sum: OnceCell::new(),
            document_currencies: xml.all(CBC, "DocumentCurrencyCode"),
            tax_currencies: xml.all(CBC, "TaxCurrencyCode"),
        }
    }

    pub fn contexts(&self, check: Check) -> Vec<NodeId> {
        let xml = self.xml;
        match check {
            Check::Identity(check) => check.contexts(xml),
            Check::LineSum | Check::TotalScale(_) => xml.all(CAC, "LegalMonetaryTotal"),
            Check::InclusiveTotal => vec![0],
            Check::ItemName => {
                let mut lines = xml.all(CAC, "InvoiceLine");
                lines.extend(xml.all(CAC, "CreditNoteLine"));
                lines.sort_unstable();
                lines
            }
            Check::LineAllowanceScale(_) => xml
                .all(CAC, "AllowanceCharge")
                .into_iter()
                .filter(|&id| {
                    xml.node(id).parent.is_some_and(|parent| {
                        xml.is(parent, CAC, "InvoiceLine") || xml.is(parent, CAC, "CreditNoteLine")
                    })
                })
                .collect(),
            Check::TaxSum => xml.children(0, CAC, "TaxTotal"),
            Check::TaxScale(currency) => {
                let currencies = if currency == "DocumentCurrencyCode" {
                    &self.document_currencies
                } else {
                    &self.tax_currencies
                };
                xml.all(CBC, "TaxAmount")
                    .into_iter()
                    .filter(|&id| {
                        xml.node(id).parent.is_some_and(|parent| {
                            xml.is(parent, CAC, "TaxTotal")
                                && xml
                                    .node(parent)
                                    .parent
                                    .is_some_and(|invoice| xml.is(invoice, UBL, "Invoice"))
                        }) && xml.attribute(id, "", "currencyID").is_some_and(|value| {
                            currencies
                                .iter()
                                .any(|&currency| xml.node(currency).text == value)
                        })
                    })
                    .collect()
            }
            Check::TaxCurrency | Check::BareTaxTotal => self.tax_currencies.clone(),
        }
    }

    fn decimal(&self, nodes: &[NodeId]) -> Result<Option<ExactDecimal>, FailureKind> {
        self.xml
            .singleton_text(nodes)?
            .map(|text| ExactDecimal::parse(text, self.digits))
            .transpose()
    }

    fn amount(&self, parent: NodeId, field: &str) -> Result<Option<ExactDecimal>, FailureKind> {
        self.decimal(&self.xml.children(parent, CBC, field))
    }

    fn sum(&self, parents: &[NodeId], field: &str) -> Result<ExactDecimal, FailureKind> {
        let mut total = ExactDecimal::zero();
        for &parent in parents {
            if let Some(amount) = self.amount(parent, field)? {
                total = total.add(&amount, self.digits)?;
            }
        }
        Ok(total)
    }

    fn scale(&self, nodes: &[NodeId]) -> Result<bool, FailureKind> {
        // substring-after((), '.') is the empty string. Whitespace following the
        // decimal point counts, and string-length counts Unicode code points.
        Ok(self
            .xml
            .singleton_text(nodes)?
            .unwrap_or("")
            .split_once('.')
            .is_none_or(|(_, fraction)| fraction.chars().count() <= 2))
    }

    pub fn passes(&self, check: Check, node: NodeId) -> Result<bool, FailureKind> {
        let xml = self.xml;
        match check {
            Check::Identity(check) => check.passes(xml, node),
            Check::LineSum => {
                let amount = self.amount(node, "LineExtensionAmount")?;
                let sum = self
                    .line_sum
                    .get_or_init(|| {
                        let mut lines = xml.all(CAC, "InvoiceLine");
                        lines.extend(xml.all(CAC, "CreditNoteLine"));
                        lines.sort_unstable();
                        self.sum(&lines, "LineExtensionAmount")
                    })
                    .as_ref()
                    .map_err(Clone::clone)?;
                Ok(amount.is_some_and(|amount| amount == sum.round(2)))
            }
            Check::TotalScale(field) => self.scale(&xml.children(node, CBC, field)),
            Check::InclusiveTotal => self.inclusive_total(),
            Check::ItemName => Ok(xml.children(node, CAC, "Item").iter().any(|&item| {
                xml.children(item, CBC, "Name")
                    .iter()
                    .any(|&name| !xml.node(name).text.is_empty())
            })),
            Check::LineAllowanceScale(field) => {
                if !self.has_indicator(node, false)? {
                    return Ok(true);
                }
                let line = xml
                    .node(node)
                    .parent
                    .expect("selected allowance has a parent");
                if xml.is(line, CAC, "InvoiceLine")
                    && (xml
                        .node(line)
                        .parent
                        .is_some_and(|root| xml.is_document_root(root))
                        || self.has_indicator(node, true)?)
                {
                    // cen:template:007 is empty but wins for direct lines.
                    // cen:template:009 also wins for any InvoiceLine charge,
                    // including a repeated indicator sequence containing both.
                    return Ok(true);
                }
                self.scale(&xml.children(node, CBC, field))
            }
            Check::TaxSum => {
                let subtotals = xml.children(node, CAC, "TaxSubtotal");
                if subtotals.is_empty() {
                    return Ok(true);
                }
                let amount = self.amount(node, "TaxAmount")?;
                let sum = self.sum(&subtotals, "TaxAmount")?.round(2);
                Ok(amount.is_some_and(|amount| amount == sum))
            }
            // These are distinct patterns (d7e353 and d7e362); next-match runs
            // both on a SAR tax amount when both currency codes are SAR.
            Check::TaxScale(_) => self.scale(&[node]),
            Check::TaxCurrency => Ok(normalize_space(&xml.node(node).text.to_uppercase()) == "SAR"),
            Check::BareTaxTotal => Ok(xml.node(node).parent.map_or(0, |parent| {
                xml.children(parent, CAC, "TaxTotal")
                    .into_iter()
                    .filter(|&tax| xml.children(tax, CAC, "TaxSubtotal").is_empty())
                    .count()
            }) == 1),
        }
    }

    fn has_indicator(&self, node: NodeId, expected: bool) -> Result<bool, FailureKind> {
        for id in self.xml.children(node, CBC, "ChargeIndicator") {
            let value = match normalize_space(&self.xml.node(id).text).as_str() {
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

    fn inclusive_total(&self) -> Result<bool, FailureKind> {
        let xml = self.xml;
        // The full conjunction is inside `every ... satisfies`. With no
        // DocumentCurrencyCode its value is true, even if totals differ.
        for currency in xml.children(0, CBC, "DocumentCurrencyCode") {
            let taxes = xml.children(0, CAC, "TaxTotal");
            let mut matching = 0;
            for &tax in &taxes {
                let amounts: Vec<_> = xml
                    .children(tax, CBC, "TaxAmount")
                    .into_iter()
                    .filter(|&amount| {
                        xml.attribute(amount, "", "currencyID")
                            == Some(xml.node(currency).text.as_str())
                    })
                    .collect();
                if self.decimal(&amounts)?.is_some() {
                    matching += 1;
                }
            }
            if matching == 0 {
                return Ok(false);
            }
            let totals = xml.children(0, CAC, "LegalMonetaryTotal");
            // Each path step constructs at most one decimal per total; the
            // arithmetic operand as a whole must still be a singleton.
            let mut exclusive = Vec::new();
            let mut inclusive = Vec::new();
            for total in totals {
                if let Some(amount) = self.amount(total, "TaxExclusiveAmount")? {
                    exclusive.push(amount);
                }
                if let Some(amount) = self.amount(total, "TaxInclusiveAmount")? {
                    inclusive.push(amount);
                }
            }
            let exclusive = match exclusive.as_slice() {
                [] => return Ok(false),
                [value] => value,
                _ => return Err(FailureKind::Cardinality),
            };
            let sum = self
                .subtotal_sum
                .get_or_init(|| {
                    let subtotals: Vec<_> = taxes
                        .iter()
                        .flat_map(|&tax| xml.children(tax, CAC, "TaxSubtotal"))
                        .collect();
                    self.sum(&subtotals, "TaxAmount")
                })
                .as_ref()
                .map_err(Clone::clone)?;
            let expected = exclusive.add(sum, self.digits)?.round(2);
            if !inclusive.contains(&expected) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
