//! Explicit coverage, findings, and failures for local ZATCA validation.
use super::{Severity, ValidationFinding, ValidationLayer, ValidationLocation, ValidationReport};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

/// Caller context for a local ZATCA validation run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ZatcaValidationOptions {
    /// Evaluation instant and implicit timezone; omitted values use the validator's clock.
    pub evaluated_at: Option<DateTime<FixedOffset>>,
    /// Expected predecessor invoice hash, when chain context is available.
    pub previous_invoice_hash: Option<String>,
}

/// Independently reported stages of the local validation profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ZatcaStage {
    Xsd,
    Cen,
    Ksa,
    Signature,
    Qr,
    PreviousInvoiceHash,
}

/// Whether a stage ran and produced a complete result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ZatcaStageStatus {
    NotRun,
    /// All checks finished; findings can still contain validation errors.
    Completed,
    /// The selected profile does not require this stage for the document.
    NotApplicable,
    /// Required caller context was unavailable.
    ContextRequired,
    /// Execution stopped before the stage completed; findings may be partial.
    EvaluationFailed,
}

/// Pinned source used to implement a business-rule profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZatcaRuleSource {
    pub stylesheet: String,
    pub sha256: String,
}

/// A finding with its individual source assertion, when applicable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZatcaFinding {
    pub assertion_site: Option<String>,
    #[serde(flatten)]
    pub finding: ValidationFinding,
}

/// Coverage and findings from one stage, including partial execution results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZatcaStageReport {
    pub stage: ZatcaStage,
    pub status: ZatcaStageStatus,
    pub provenance: Option<ZatcaRuleSource>,
    pub evaluated_assertions: Vec<String>,
    pub findings: Vec<ZatcaFinding>,
}

/// Results of local validation with explicit stage coverage.
///
/// Completion and validity describe only this local profile. They do not
/// establish acceptance by a remote service or certificate issuer trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZatcaValidationReport {
    pub schema_version: u32,
    pub profile: String,
    pub evaluated_at: DateTime<FixedOffset>,
    pub stages: Vec<ZatcaStageReport>,
}

impl ZatcaValidationReport {
    /// Whether every required stage finished exactly once.
    ///
    /// Signature and QR may be explicitly inapplicable. Other stages, including
    /// previous-invoice-hash verification, must have completed.
    pub fn is_complete(&self) -> bool {
        use ZatcaStage::*;
        self.stages.len() == 6
            && [Xsd, Cen, Ksa, Signature, Qr, PreviousInvoiceHash]
                .into_iter()
                .all(|stage| {
                    self.unique_stage(stage).is_some_and(|result| {
                        result.status == ZatcaStageStatus::Completed
                            || (matches!(stage, Signature | Qr)
                                && result.status == ZatcaStageStatus::NotApplicable)
                    })
                })
    }

    /// Whether any stage, including an incomplete stage, reported an error.
    pub fn has_errors(&self) -> bool {
        self.stages.iter().any(|stage| {
            stage
                .findings
                .iter()
                .any(|finding| finding.finding.severity == Severity::Error)
        })
    }

    /// Whether local validation is complete and contains no error findings.
    pub fn is_valid(&self) -> bool {
        self.is_complete() && !self.has_errors()
    }

    /// Aggregate findings using the shared report format.
    ///
    /// Partial findings are retained. A layer is marked checked only when its
    /// corresponding stages completed, and business rules require both CEN and
    /// KSA. Duplicate stage entries never establish completed coverage.
    pub fn validation_report(&self) -> ValidationReport {
        let completed = |stage| {
            self.unique_stage(stage)
                .is_some_and(|report| report.status == ZatcaStageStatus::Completed)
        };
        let mut layers_checked = Vec::new();
        if completed(ZatcaStage::Xsd) {
            layers_checked.push(ValidationLayer::Xsd);
        }
        if completed(ZatcaStage::Cen) && completed(ZatcaStage::Ksa) {
            layers_checked.push(ValidationLayer::BusinessRules);
        }
        for (stage, layer) in [
            (ZatcaStage::Signature, ValidationLayer::Signature),
            (ZatcaStage::Qr, ValidationLayer::Qr),
            (
                ZatcaStage::PreviousInvoiceHash,
                ValidationLayer::PreviousInvoiceHash,
            ),
        ] {
            if completed(stage) {
                layers_checked.push(layer);
            }
        }
        ValidationReport {
            layers_checked,
            issues: self
                .stages
                .iter()
                .flat_map(|stage| stage.findings.iter().map(|finding| finding.finding.clone()))
                .collect(),
        }
    }

    fn unique_stage(&self, stage: ZatcaStage) -> Option<&ZatcaStageReport> {
        let mut matches = self.stages.iter().filter(|report| report.stage == stage);
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }
}

/// Classification of a validation execution failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ZatcaFailureKind {
    InvalidXml,
    UnsupportedXml,
    CapacityExceeded,
    InvalidContext,
    RuleEvaluation,
    Schema,
    Integrity,
}

/// Execution failure with all findings obtained before validation stopped.
#[derive(Debug, thiserror::Error, Serialize)]
#[error("{message}")]
pub struct ZatcaValidationError {
    pub kind: ZatcaFailureKind,
    pub stage: Option<ZatcaStage>,
    pub assertion_site: Option<String>,
    pub location: Option<ValidationLocation>,
    pub message: String,
    pub report: Box<ZatcaValidationReport>,
}

impl ZatcaValidationError {
    /// Shared classification used by bindings.
    pub fn kind(&self) -> crate::ErrorKind {
        match self.kind {
            ZatcaFailureKind::InvalidXml => crate::ErrorKind::Xml,
            ZatcaFailureKind::UnsupportedXml
            | ZatcaFailureKind::CapacityExceeded
            | ZatcaFailureKind::InvalidContext => crate::ErrorKind::InvalidInput,
            ZatcaFailureKind::RuleEvaluation => crate::ErrorKind::Validation,
            ZatcaFailureKind::Schema => crate::ErrorKind::Parse,
            ZatcaFailureKind::Integrity => crate::ErrorKind::Crypto,
        }
    }
}

#[cfg(test)]
#[path = "zatca_report_tests.rs"]
mod tests;
