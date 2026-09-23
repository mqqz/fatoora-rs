//! Explicit pipeline for the pinned SDK's local validation stages.
use super::{
    ValidationLayer, ValidationLocation, ZatcaFailureKind, ZatcaFinding, ZatcaRuleSource,
    ZatcaStage, ZatcaStageReport, ZatcaStageStatus, ZatcaValidationError, ZatcaValidationOptions,
    ZatcaValidationReport,
    business_rules::{self, FailureKind, Source, StageStatus},
    integrity, validate_xml_invoice_report_from_str,
};
use crate::config::Config;

/// Validate raw XML against the pinned ZATCA SDK profile using local checks.
///
/// Schema and business-rule rejections return a report. Warnings remain visible.
/// Malformed input, resource exhaustion, or an interrupted evaluation return an
/// error carrying the partial report. `report.is_valid()` requires every
/// applicable stage to complete without errors; an empty finding list alone
/// never establishes success.
///
/// The default clock is UTC, captured once. Supply `evaluated_at` to reproduce
/// a result or specify an implicit timezone. `previous_invoice_hash` is required
/// to verify chain continuity; omitting it leaves that stage `context_required`.
/// The SDK profile omits signature/QR checks for standard invoices. Local
/// signature checks establish content/key integrity, not issuer trust, remote
/// acceptance, certificate revocation, or invoice history.
///
/// # Errors
/// Returns [`ZatcaValidationError`] with completed and partial stage findings.
pub fn validate_zatca_invoice_from_str(
    xml: &str,
    config: &Config,
    options: &ZatcaValidationOptions,
) -> Result<ZatcaValidationReport, ZatcaValidationError> {
    let instant = options
        .evaluated_at
        .unwrap_or_else(|| chrono::Utc::now().fixed_offset());
    let mut report = ZatcaValidationReport {
        schema_version: 1,
        profile: "zatca-sdk-238-R3.4.8".into(),
        evaluated_at: instant,
        stages: [
            ZatcaStage::Xsd,
            ZatcaStage::Cen,
            ZatcaStage::Ksa,
            ZatcaStage::Signature,
            ZatcaStage::Qr,
            ZatcaStage::PreviousInvoiceHash,
        ]
        .into_iter()
        .map(|stage| ZatcaStageReport {
            stage,
            status: ZatcaStageStatus::NotRun,
            provenance: provenance(stage),
            evaluated_assertions: vec![],
            findings: vec![],
        })
        .collect(),
    };
    if options
        .previous_invoice_hash
        .as_deref()
        .is_some_and(|hash| !integrity::valid_previous_hash(hash))
    {
        return Err(failure(report, ZatcaFailureKind::InvalidContext,None,"previous_invoice_hash must be a canonical base64 SHA-256 digest or SDK hexadecimal digest".into()));
    }
    if let Err(kind) = business_rules::check_input(xml) {
        return Err(failure(report, failure_kind(&kind), None, kind.to_string()));
    }
    let xsd = match validate_xml_invoice_report_from_str(xml, config) {
        Ok(xsd) => xsd,
        Err(error) => {
            return Err(failure(
                report,
                ZatcaFailureKind::Schema,
                Some(ZatcaStage::Xsd),
                format!("{error}: {error:?}"),
            ));
        }
    };
    let rejected = xsd.has_errors();
    report.stages[0].status = ZatcaStageStatus::Completed;
    report.stages[0].findings = xsd
        .issues
        .into_iter()
        .map(|finding| ZatcaFinding {
            assertion_site: None,
            finding,
        })
        .collect();
    if rejected {
        return Ok(report);
    }
    let rules = business_rules::evaluate(
        xml,
        &business_rules::EvaluationContext {
            instant,
            limits: Default::default(),
        },
    );
    let (rules, error) = match rules {
        Ok(report) => (report, None),
        Err(f) => {
            let f = *f;
            (
                f.report,
                Some((f.failed_source, f.site, f.location, f.kind)),
            )
        }
    };
    for stage in rules.stages {
        let index = match stage.source {
            Source::Cen => 1,
            Source::Ksa => 2,
        };
        let result = &mut report.stages[index];
        result.status = match stage.status {
            StageStatus::NotRun => ZatcaStageStatus::NotRun,
            StageStatus::Completed => ZatcaStageStatus::Completed,
            StageStatus::EvaluationFailed | StageStatus::EvaluatedSubset => {
                ZatcaStageStatus::EvaluationFailed
            }
        };
        result.evaluated_assertions = stage
            .evaluated_sites
            .into_iter()
            .map(str::to_owned)
            .collect();
        result.findings = stage
            .findings
            .into_iter()
            .map(|finding| ZatcaFinding {
                assertion_site: Some(finding.site.into()),
                finding: super::ValidationFinding {
                    layer: ValidationLayer::BusinessRules,
                    code: finding.code.into(),
                    severity: finding.severity,
                    message: finding.message.into(),
                    location: Some(ValidationLocation::XPath(finding.location)),
                },
            })
            .collect();
    }
    if let Some((source, site, location, kind)) = error {
        let stage = source.map(|source| match source {
            Source::Cen => ZatcaStage::Cen,
            Source::Ksa => ZatcaStage::Ksa,
        });
        let mut error = failure(report, failure_kind(&kind), stage, kind.to_string());
        error.assertion_site = site.map(str::to_owned);
        error.location = location.map(ValidationLocation::XPath);
        return Err(error);
    }
    if let Err((stage, message)) =
        integrity::apply(xml, options.previous_invoice_hash.as_deref(), &mut report)
    {
        return Err(failure(
            report,
            ZatcaFailureKind::Integrity,
            Some(stage),
            message,
        ));
    }
    Ok(report)
}
fn provenance(stage: ZatcaStage) -> Option<ZatcaRuleSource> {
    let (stylesheet, sha256) = match stage {
        ZatcaStage::Cen => (
            "CEN-EN16931-UBL.xsl",
            "378a7a4d697aa96e05edb4649ab4536b33546b8e288453324a5668c3e15735b0",
        ),
        ZatcaStage::Ksa => (
            "20210819_ZATCA_E-invoice_Validation_Rules.xsl",
            "3312e1938829b8972dacf19a3d933deeb97cb71c7e982c56a434b76cc0e5f0c4",
        ),
        _ => return None,
    };
    Some(ZatcaRuleSource {
        stylesheet: stylesheet.into(),
        sha256: sha256.into(),
    })
}
fn failure_kind(kind: &FailureKind) -> ZatcaFailureKind {
    match kind {
        FailureKind::InvalidXml(_) => ZatcaFailureKind::InvalidXml,
        FailureKind::UnsupportedXml(_) => ZatcaFailureKind::UnsupportedXml,
        FailureKind::Limit(_) => ZatcaFailureKind::CapacityExceeded,
        _ => ZatcaFailureKind::RuleEvaluation,
    }
}
fn failure(
    mut report: ZatcaValidationReport,
    kind: ZatcaFailureKind,
    stage: Option<ZatcaStage>,
    message: String,
) -> ZatcaValidationError {
    if let Some(stage) = stage {
        report
            .stages
            .iter_mut()
            .find(|s| s.stage == stage)
            .expect("pipeline stage")
            .status = ZatcaStageStatus::EvaluationFailed;
    }
    ZatcaValidationError {
        kind,
        stage,
        assertion_site: None,
        location: None,
        message,
        report: Box::new(report),
    }
}
