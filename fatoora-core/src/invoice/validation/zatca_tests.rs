use super::*;
const SEED: &str =
    "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==";
fn options() -> ZatcaValidationOptions {
    ZatcaValidationOptions {
        evaluated_at: Some("2026-09-23T12:00:00+03:00".parse().unwrap()),
        previous_invoice_hash: Some(SEED.into()),
    }
}
const STANDARD: &str =
    include_str!("../../../tests/fixtures/sdk-parity/cases/standard-invoice/input.xml");
const SIMPLIFIED: &str =
    include_str!("../../../tests/fixtures/sdk-parity/cases/simplified-invoice/sdk-signed.xml");
#[test]
fn complete_pipeline_returns_warnings_sources_sites_and_explicit_applicability() {
    for (xml, signature) in [
        (STANDARD, ZatcaStageStatus::NotApplicable),
        (SIMPLIFIED, ZatcaStageStatus::Completed),
    ] {
        let report = validate_zatca_invoice_from_str(xml, &Config::default(), &options()).unwrap();
        assert!(report.is_valid(), "{report:#?}");
        assert_eq!(report.stages[1].evaluated_assertions.len(), 105);
        assert_eq!(report.stages[2].evaluated_assertions.len(), 152);
        assert_eq!(report.stages[3].status, signature);
        assert!(
            report.stages[2]
                .findings
                .iter()
                .any(|f| f.finding.severity == Severity::Warning)
        );
        assert!(
            report.stages[2]
                .findings
                .iter()
                .all(|f| f.assertion_site.is_some()
                    && matches!(f.finding.location, Some(ValidationLocation::XPath(_))))
        );
        assert_eq!(report.evaluated_at, options().evaluated_at.unwrap());
        assert!(
            report
                .validation_report()
                .layers_checked
                .contains(&ValidationLayer::BusinessRules)
        );
        let json = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serde_json::from_str::<ZatcaValidationReport>(&json).unwrap(),
            report
        );
    }
}
#[test]
fn schema_rejection_stops_dependent_stages_but_legacy_contract_is_unchanged() {
    let report =
        validate_zatca_invoice_from_str("<wrong/>", &Config::default(), &options()).unwrap();
    assert!(report.has_errors());
    assert!(!report.is_complete());
    assert!(!report.is_valid());
    assert_eq!(report.stages[0].status, ZatcaStageStatus::Completed);
    assert!(
        report.stages[1..]
            .iter()
            .all(|s| s.status == ZatcaStageStatus::NotRun)
    );
    let legacy = validate_xml_invoice_report_from_str(STANDARD, &Config::default()).unwrap();
    assert_eq!(legacy.layers_checked, vec![ValidationLayer::Xsd]);
    assert!(!legacy.has_errors());
}
#[test]
fn missing_chain_context_is_explicit_and_wrong_context_rejects() {
    let mut opts = options();
    opts.previous_invoice_hash = None;
    let report = validate_zatca_invoice_from_str(STANDARD, &Config::default(), &opts).unwrap();
    assert!(!report.is_complete());
    assert!(!report.is_valid());
    assert!(!report.has_errors());
    assert_eq!(report.stages[5].status, ZatcaStageStatus::ContextRequired);
    opts.previous_invoice_hash = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
    let report = validate_zatca_invoice_from_str(STANDARD, &Config::default(), &opts).unwrap();
    assert!(report.is_complete());
    assert!(report.has_errors());
    assert!(!report.is_valid());
}
#[test]
fn malformed_unsupported_and_over_limit_xml_never_look_like_success() {
    for (xml, kind) in [
        ("<Invoice", ZatcaFailureKind::InvalidXml),
        (
            "<!DOCTYPE Invoice [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><Invoice>&x;</Invoice>",
            ZatcaFailureKind::UnsupportedXml,
        ),
    ] {
        let error =
            validate_zatca_invoice_from_str(xml, &Config::default(), &options()).unwrap_err();
        assert_eq!(error.kind, kind);
        assert!(!error.report.is_valid());
        assert!(
            error
                .report
                .stages
                .iter()
                .all(|s| s.status == ZatcaStageStatus::NotRun)
        );
    }
    let xml = "x".repeat(8 * 1024 * 1024 + 1);
    let error = validate_zatca_invoice_from_str(&xml, &Config::default(), &options()).unwrap_err();
    assert_eq!(error.kind, ZatcaFailureKind::CapacityExceeded);
}
#[test]
fn execution_failures_keep_completed_sources_and_original_locations() {
    // currencyID is schema-valid text but an invalid XPath regex in the pinned KSA rule.
    let xml = STANDARD.replacen(
        "<cbc:LineExtensionAmount currencyID=\"SAR\">300.00",
        "<cbc:LineExtensionAmount currencyID=\"[\">300.00",
        1,
    );
    assert_ne!(xml, STANDARD);
    let error = validate_zatca_invoice_from_str(&xml, &Config::default(), &options()).unwrap_err();
    assert_eq!(error.kind, ZatcaFailureKind::RuleEvaluation);
    assert_eq!(error.stage, Some(ZatcaStage::Ksa));
    assert_eq!(
        error.assertion_site.as_deref(),
        Some("ksa:112:BR-KSA-CL-02")
    );
    assert!(matches!(error.location, Some(ValidationLocation::XPath(_))));
    assert_eq!(error.report.stages[1].status, ZatcaStageStatus::Completed);
    assert_eq!(
        error.report.stages[2].status,
        ZatcaStageStatus::EvaluationFailed
    );
    assert!(
        error.report.stages[3..]
            .iter()
            .all(|s| s.status == ZatcaStageStatus::NotRun)
    );
    assert!(
        !error
            .report
            .validation_report()
            .layers_checked
            .contains(&ValidationLayer::BusinessRules)
    );
}
#[test]
fn invalid_context_is_reported_before_validation() {
    let mut opts = options();
    opts.previous_invoice_hash = Some("bad".into());
    let error = validate_zatca_invoice_from_str(STANDARD, &Config::default(), &opts).unwrap_err();
    assert_eq!(error.kind, ZatcaFailureKind::InvalidContext);
    assert!(
        error
            .report
            .stages
            .iter()
            .all(|s| s.status == ZatcaStageStatus::NotRun)
    );
}

#[test]
fn schema_valid_business_rejection_returns_complete_report() {
    let xml = STANDARD.replace(
        "<cbc:UUID>b2a43c49-3aab-4e3b-9d67-0da45a5e33cc</cbc:UUID>",
        "",
    );
    assert_ne!(xml, STANDARD);
    let report = validate_zatca_invoice_from_str(&xml, &Config::default(), &options()).unwrap();
    assert!(report.is_complete());
    assert!(report.has_errors());
    assert!(!report.is_valid());
    assert!(report.stages[0].findings.is_empty());
    assert!(
        report.stages[2]
            .findings
            .iter()
            .any(|f| f.finding.code == "BR-KSA-03" && f.finding.severity == Severity::Error)
    );
}
