use super::*;

fn report() -> ZatcaValidationReport {
    ZatcaValidationReport {
        schema_version: 1,
        profile: "zatca-sdk-238-R3.4.8".to_owned(),
        evaluated_at: chrono::DateTime::parse_from_rfc3339("2026-09-23T12:00:00+03:00").unwrap(),
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
            status: ZatcaStageStatus::Completed,
            provenance: None,
            evaluated_assertions: Vec::new(),
            findings: Vec::new(),
        })
        .collect(),
    }
}

fn finding(severity: Severity) -> ZatcaFinding {
    ZatcaFinding {
        assertion_site: Some("ksa:017:BR-KSA-80".to_owned()),
        finding: ValidationFinding {
            layer: ValidationLayer::BusinessRules,
            code: "BR-KSA-80".to_owned(),
            severity,
            message: "Prepayment amounts differ".to_owned(),
            location: Some(ValidationLocation::Xml {
                line: 12,
                column: Some(3),
            }),
        },
    }
}

#[test]
fn completion_requires_each_stage_once_and_never_accepts_empty_reports() {
    assert!(report().is_complete());
    let mut empty = report();
    empty.stages.clear();
    assert!(!empty.is_complete());
    assert!(!empty.is_valid());
    for index in 0..6 {
        let mut missing = report();
        missing.stages.remove(index);
        assert!(!missing.is_complete());
        let mut repeated = report();
        repeated.stages.push(repeated.stages[index].clone());
        assert!(!repeated.is_complete());
        let mut substituted = report();
        substituted.stages[index] = substituted.stages[(index + 1) % 6].clone();
        assert!(!substituted.is_complete());
    }
    let mut reordered = report();
    reordered.stages.reverse();
    assert!(reordered.is_complete());
}

#[test]
fn only_signature_and_qr_can_complete_with_not_applicable_status() {
    for index in 0..6 {
        for status in [
            ZatcaStageStatus::NotRun,
            ZatcaStageStatus::NotApplicable,
            ZatcaStageStatus::ContextRequired,
            ZatcaStageStatus::EvaluationFailed,
        ] {
            let mut result = report();
            result.stages[index].status = status;
            let expected = matches!(index, 3 | 4) && status == ZatcaStageStatus::NotApplicable;
            assert_eq!(result.is_complete(), expected, "stage {index}: {status:?}");
            assert_eq!(result.is_valid(), expected);
        }
    }
}

#[test]
fn warnings_allow_validity_but_errors_remain_distinct_from_completion() {
    let mut result = report();
    result.stages[2].findings.push(finding(Severity::Warning));
    assert!(result.is_complete());
    assert!(!result.has_errors());
    assert!(result.is_valid());
    result.stages[2].findings.push(finding(Severity::Error));
    assert!(result.is_complete());
    assert!(result.has_errors());
    assert!(!result.is_valid());
}

#[test]
fn aggregate_retains_partial_findings_without_claiming_their_layer_completed() {
    let mut result = report();
    result.stages[2].status = ZatcaStageStatus::EvaluationFailed;
    result.stages[2].findings.push(finding(Severity::Error));
    result.stages[3].status = ZatcaStageStatus::NotRun;
    result.stages[4].status = ZatcaStageStatus::NotRun;
    result.stages[5].status = ZatcaStageStatus::ContextRequired;
    assert!(result.has_errors());
    assert!(!result.is_complete());
    let aggregate = result.validation_report();
    assert_eq!(aggregate.layers_checked, vec![ValidationLayer::Xsd]);
    assert_eq!(aggregate.issues, vec![finding(Severity::Error).finding]);
    assert!(aggregate.has_errors());
}

#[test]
fn aggregate_business_layer_requires_both_profiles_and_lists_completed_layers_once() {
    let mut result = report();
    assert_eq!(
        result.validation_report().layers_checked,
        vec![
            ValidationLayer::Xsd,
            ValidationLayer::BusinessRules,
            ValidationLayer::Signature,
            ValidationLayer::Qr,
            ValidationLayer::PreviousInvoiceHash
        ]
    );
    for index in [1, 2] {
        result.stages[index].status = ZatcaStageStatus::NotRun;
        assert!(
            !result
                .validation_report()
                .layers_checked
                .contains(&ValidationLayer::BusinessRules)
        );
        result.stages[index].status = ZatcaStageStatus::Completed;
    }
    result.stages[3].status = ZatcaStageStatus::NotApplicable;
    result.stages[4].status = ZatcaStageStatus::NotApplicable;
    assert_eq!(
        result.validation_report().layers_checked,
        vec![
            ValidationLayer::Xsd,
            ValidationLayer::BusinessRules,
            ValidationLayer::PreviousInvoiceHash
        ]
    );
    result.stages.push(result.stages[0].clone());
    assert!(
        !result
            .validation_report()
            .layers_checked
            .contains(&ValidationLayer::Xsd)
    );
}

#[test]
fn options_default_and_json_report_roundtrip_preserve_context_and_provenance() {
    assert_eq!(
        serde_json::from_str::<ZatcaValidationOptions>("{}").unwrap(),
        ZatcaValidationOptions::default()
    );
    assert!(
        serde_json::from_str::<ZatcaValidationOptions>(r#"{"previous_invoice_has":"typo"}"#)
            .is_err()
    );
    let options = ZatcaValidationOptions {
        evaluated_at: Some(report().evaluated_at),
        previous_invoice_hash: Some("previous-hash".to_owned()),
    };
    assert_eq!(
        serde_json::from_str::<ZatcaValidationOptions>(&serde_json::to_string(&options).unwrap())
            .unwrap(),
        options
    );
    let mut result = report();
    result.stages[2].provenance = Some(ZatcaRuleSource {
        stylesheet: "20210819_ZATCA_E-invoice_Validation_Rules.xsl".to_owned(),
        sha256: "3312e1938829b8972dacf19a3d933deeb97cb71c7e982c56a434b76cc0e5f0c4".to_owned(),
    });
    result.stages[2]
        .evaluated_assertions
        .push("ksa:017:BR-KSA-80".to_owned());
    result.stages[2].findings.push(finding(Severity::Warning));
    let value = serde_json::to_value(&result).unwrap();
    assert_eq!(value["stages"][2]["stage"], "ksa");
    assert_eq!(value["stages"][2]["status"], "completed");
    assert_eq!(value["stages"][2]["findings"][0]["code"], "BR-KSA-80");
    assert!(value["stages"][2]["findings"][0].get("finding").is_none());
    assert_eq!(
        serde_json::from_value::<ZatcaValidationReport>(value).unwrap(),
        result
    );
}

#[test]
fn execution_errors_preserve_partial_reports_and_stable_error_kinds() {
    for (kind, expected) in [
        (ZatcaFailureKind::InvalidXml, crate::ErrorKind::Xml),
        (
            ZatcaFailureKind::UnsupportedXml,
            crate::ErrorKind::InvalidInput,
        ),
        (
            ZatcaFailureKind::CapacityExceeded,
            crate::ErrorKind::InvalidInput,
        ),
        (
            ZatcaFailureKind::InvalidContext,
            crate::ErrorKind::InvalidInput,
        ),
        (
            ZatcaFailureKind::RuleEvaluation,
            crate::ErrorKind::Validation,
        ),
        (ZatcaFailureKind::Schema, crate::ErrorKind::Parse),
        (ZatcaFailureKind::Integrity, crate::ErrorKind::Crypto),
    ] {
        let mut partial = report();
        partial.stages[2].status = ZatcaStageStatus::EvaluationFailed;
        partial.stages[2].findings.push(finding(Severity::Warning));
        let error = ZatcaValidationError {
            kind,
            stage: Some(ZatcaStage::Ksa),
            assertion_site: Some("ksa:017:BR-KSA-80".to_owned()),
            location: None,
            message: "validation could not finish".to_owned(),
            report: Box::new(partial),
        };
        assert_eq!(error.kind(), expected);
        assert_eq!(error.to_string(), "validation could not finish");
        let value = serde_json::to_value(&error).unwrap();
        assert_eq!(value["stage"], "ksa");
        assert_eq!(value["report"]["stages"][2]["status"], "evaluation_failed");
        assert_eq!(
            value["report"]["stages"][2]["findings"][0]["severity"],
            "warning"
        );
    }
}

#[test]
fn serialized_outcomes_are_derived_and_cannot_override_missing_coverage() {
    let mut incomplete = report();
    incomplete.stages.clear();
    let mut value = serde_json::to_value(incomplete).unwrap();
    assert_eq!(value["is_complete"], false);
    assert_eq!(value["is_valid"], false);
    value["is_complete"] = true.into();
    value["is_valid"] = true.into();
    let result: ZatcaValidationReport = serde_json::from_value(value).unwrap();
    assert!(!result.is_complete());
    assert!(!result.is_valid());
    assert_eq!(serde_json::to_value(result).unwrap()["is_valid"], false);
}
