//! Internal, explicitly incomplete evaluation of pinned SDK assertion sites.
//!
//! This is not the public ZATCA validator. No successful subset run claims that
//! either full business-rule profile, XSD, or cryptographic validation completed.
mod code_lists;
mod decimal;
mod identity;
mod ksa_adjustments;
mod ksa_buyer;
mod ksa_common;
mod ksa_currency;
mod ksa_dates;
mod ksa_exemptions;
mod ksa_fields;
mod ksa_prepayment;
mod metadata;
mod patterns;
mod rules;
mod structural;
mod totals;
mod vat;
mod xml;

use super::Severity;
use chrono::{DateTime, FixedOffset};
use serde::Serialize;

#[derive(Debug, Clone)]
pub(super) struct Limits {
    pub xml_bytes: usize,
    pub nodes: usize,
    pub depth: usize,
    pub retained_bytes: usize,
    pub decimal_digits: usize,
    pub findings: usize,
    pub finding_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            xml_bytes: 8 * 1024 * 1024,
            nodes: 100_000,
            depth: 128,
            retained_bytes: 64 * 1024 * 1024,
            decimal_digits: 4096,
            findings: 10_000,
            finding_bytes: 8 * 1024 * 1024,
        }
    }
}

/// The caller snapshots the evaluation instant and offset exactly once.
#[derive(Debug, Clone)]
pub(super) struct EvaluationContext {
    pub instant: DateTime<FixedOffset>,
    pub limits: Limits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Source {
    Cen,
    Ksa,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Self::Cen => "cen",
            Self::Ksa => "ksa",
        }
    }
    fn sdk_name(self) -> &'static str {
        match self {
            Self::Cen => "en",
            Self::Ksa => "ksa",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum StageStatus {
    NotRun,
    EvaluatedSubset,
    EvaluationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct RuleFinding {
    pub site: &'static str,
    pub code: &'static str,
    pub severity: Severity,
    pub message: &'static str,
    /// Namespace-independent XPath 1.0 expression selecting the context element.
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct StageReport {
    pub source: Source,
    pub status: StageStatus,
    /// Sites whose selected contexts were all evaluated, including empty sets.
    pub evaluated_sites: Vec<&'static str>,
    pub findings: Vec<RuleFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct SliceReport {
    pub profile: &'static str,
    pub evaluated_at: DateTime<FixedOffset>,
    pub stages: Vec<StageReport>,
}

impl SliceReport {
    fn new(context: &EvaluationContext) -> Self {
        Self {
            profile: "zatca-sdk-238-R3.4.8",
            evaluated_at: context.instant,
            stages: [Source::Cen, Source::Ksa]
                .into_iter()
                .map(|source| StageReport {
                    source,
                    status: StageStatus::NotRun,
                    evaluated_sites: Vec::new(),
                    findings: Vec::new(),
                })
                .collect(),
        }
    }
    pub fn is_complete(&self) -> bool {
        false
    }
    pub fn has_errors(&self) -> bool {
        self.stages
            .iter()
            .flat_map(|s| &s.findings)
            .any(|f| f.severity == Severity::Error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(super) enum FailureKind {
    #[error("invalid XML: {0}")]
    InvalidXml(String),
    #[error("unsupported XML: {0}")]
    UnsupportedXml(String),
    #[error("evaluation capacity exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid xs:decimal lexical value")]
    InvalidDecimal,
    #[error("invalid xs:double lexical value")]
    InvalidDouble,
    #[error("expected zero or one value, found multiple values")]
    Cardinality,
    #[error("invalid xs:boolean lexical value")]
    InvalidBoolean,
    #[error("invalid XPath regular expression")]
    InvalidRegex,
    #[error("invalid XML Schema date or time")]
    InvalidDateTime,
}

#[derive(Debug, thiserror::Error)]
#[error("business-rule evaluation failed: {kind}")]
pub(super) struct EvaluationFailure {
    pub report: SliceReport,
    pub failed_source: Option<Source>,
    pub site: Option<&'static str>,
    pub location: Option<String>,
    pub kind: FailureKind,
}

/// Evaluate the implemented sites only. Order is source, assertion site, document.
pub(super) fn evaluate_slice(
    input: &str,
    context: &EvaluationContext,
) -> Result<SliceReport, Box<EvaluationFailure>> {
    evaluate_matching(input, context, |_| true)
}

fn evaluate_matching(
    input: &str,
    context: &EvaluationContext,
    include: impl Fn(&metadata::Rule) -> bool,
) -> Result<SliceReport, Box<EvaluationFailure>> {
    let mut report = SliceReport::new(context);
    let view = match xml::XmlView::parse(input, &context.limits) {
        Ok(view) => view,
        Err(kind) => {
            return Err(Box::new(EvaluationFailure {
                report,
                failed_source: None,
                site: None,
                location: None,
                kind,
            }));
        }
    };
    if !view.is_document_root(0) {
        return Err(Box::new(EvaluationFailure {
            report,
            failed_source: None,
            site: None,
            location: Some(view.node(0).location.clone()),
            kind: FailureKind::UnsupportedXml("expected UBL Invoice or CreditNote".into()),
        }));
    }
    let facts = rules::Facts::new(&view, context.limits.decimal_digits, context.instant);
    let mut finding_count = 0;
    let mut finding_bytes = 0usize;
    for index in 0..report.stages.len() {
        let source = report.stages[index].source;
        for rule in metadata::RULES
            .iter()
            .filter(|r| r.source == source && include(r))
        {
            let nodes = match facts.contexts(rule.check) {
                Ok(nodes) => nodes,
                Err(kind) => {
                    report.stages[index].status = StageStatus::EvaluationFailed;
                    return Err(Box::new(EvaluationFailure {
                        report,
                        failed_source: Some(source),
                        site: Some(rule.site),
                        location: None,
                        kind,
                    }));
                }
            };
            for node in nodes {
                let location = facts.location(rule.check, node);
                let bytes = location.len() + rule.message.len();
                let result = facts.passes(rule.check, node).and_then(|passed| {
                    if !passed && finding_count >= context.limits.findings {
                        Err(FailureKind::Limit("findings"))
                    } else if !passed
                        && bytes > context.limits.finding_bytes.saturating_sub(finding_bytes)
                    {
                        Err(FailureKind::Limit("finding bytes"))
                    } else {
                        Ok(passed)
                    }
                });
                match result {
                    Ok(true) => {}
                    Ok(false) => {
                        finding_count += 1;
                        finding_bytes += bytes;
                        report.stages[index].findings.push(RuleFinding {
                            site: rule.site,
                            code: rule.code,
                            severity: rule.severity,
                            message: rule.message,
                            location: location.into_owned(),
                        });
                    }
                    Err(kind) => {
                        report.stages[index].status = StageStatus::EvaluationFailed;
                        return Err(Box::new(EvaluationFailure {
                            report,
                            failed_source: Some(source),
                            site: Some(rule.site),
                            location: Some(location.into_owned()),
                            kind,
                        }));
                    }
                }
            }
            report.stages[index].evaluated_sites.push(rule.site);
        }
        report.stages[index].status = StageStatus::EvaluatedSubset;
    }
    Ok(report)
}

#[cfg(test)]
mod numeric_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod xml_tests;

#[cfg(test)]
mod identity_tests;

#[cfg(test)]
mod structural_tests;

#[cfg(test)]
mod code_list_tests;

#[cfg(test)]
mod totals_tests;

#[cfg(test)]
mod ksa_field_tests;

#[cfg(test)]
mod ksa_buyer_tests;

#[cfg(test)]
mod ksa_common_tests;

#[cfg(test)]
mod vat_tests;

#[cfg(test)]
mod ksa_adjustment_tests;

#[cfg(test)]
mod ksa_exemption_tests;

#[cfg(test)]
mod pattern_tests;

#[cfg(test)]
mod ksa_currency_tests;

#[cfg(test)]
mod ksa_date_tests;

#[cfg(test)]
mod ksa_prepayment_tests;
