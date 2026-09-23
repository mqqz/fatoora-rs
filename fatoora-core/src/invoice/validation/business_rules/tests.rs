use super::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

// Primitive contracts use deliberately incomplete XML and isolate the original
// slice. Corpus comparisons below always run every implemented rule.
fn evaluate_slice(
    input: &str,
    context: &EvaluationContext,
) -> Result<SliceReport, Box<EvaluationFailure>> {
    evaluate_matching(input, context, |r| {
        matches!(
            r.check,
            rules::Check::LineSum
                | rules::Check::TotalScale(_)
                | rules::Check::InclusiveTotal
                | rules::Check::ItemName
                | rules::Check::LineAllowanceScale(_)
                | rules::Check::TaxSum
                | rules::Check::TaxScale(_)
                | rules::Check::TaxCurrency
                | rules::Check::BareTaxTotal
        )
    })
}

fn context() -> EvaluationContext {
    EvaluationContext {
        instant: "2026-09-23T12:00:00+03:00".parse().unwrap(),
        limits: Limits::default(),
    }
}

fn invoice(body: &str) -> String {
    format!(
        r#"<Invoice xmlns="{}" xmlns:cac="{}" xmlns:cbc="{}">{body}</Invoice>"#,
        xml::UBL,
        xml::CAC,
        xml::CBC
    )
}

fn run(body: &str) -> SliceReport {
    evaluate_slice(&invoice(body), &context()).unwrap()
}

fn findings<'a>(report: &'a SliceReport, id: &str) -> Vec<&'a RuleFinding> {
    report
        .stages
        .iter()
        .flat_map(|s| &s.findings)
        .filter(|f| f.code == id)
        .collect()
}

#[test]
fn successful_subset_never_claims_full_business_validation() {
    let report = run("");
    assert!(!report.is_complete());
    assert!(!report.has_errors());
    assert_eq!(report.evaluated_at, context().instant);
    assert_eq!(report.stages.len(), 2);
    assert!(
        report
            .stages
            .iter()
            .all(|s| s.status == StageStatus::EvaluatedSubset)
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["profile"], "zatca-sdk-238-R3.4.8");
    assert_eq!(json["stages"][0]["status"], "evaluated_subset");
    assert_eq!(json["stages"][0]["source"], "cen");
    assert!(
        json["stages"][0]["evaluated_sites"]
            .as_array()
            .unwrap()
            .len()
            > 10
    );
}

#[test]
fn lexical_scale_missing_values_and_unicode_characters_have_distinct_meanings() {
    for (value, count) in [
        ("1.00", 0),
        ("1.000", 1),
        ("1.00 ", 1),
        ("1.💰💰", 0),
        ("1.💰💰💰", 1),
    ] {
        let report = run(&format!(
            "<cac:LegalMonetaryTotal><cbc:PrepaidAmount>{value}</cbc:PrepaidAmount></cac:LegalMonetaryTotal>"
        ));
        assert_eq!(findings(&report, "BR-DEC-16").len(), count, "{value}");
    }
    assert!(findings(&run("<cac:LegalMonetaryTotal/>"), "BR-DEC-16").is_empty());
    let body = "<cac:LegalMonetaryTotal><cbc:PrepaidAmount>0</cbc:PrepaidAmount><cbc:PrepaidAmount>0</cbc:PrepaidAmount></cac:LegalMonetaryTotal>";
    let error = evaluate_slice(&invoice(body), &context()).unwrap_err();
    assert_eq!(error.kind, FailureKind::Cardinality);
    assert_eq!(error.site, Some("cen:028:BR-DEC-16"));
}

#[test]
fn decimal_totals_use_all_lines_and_xpath_negative_midpoints() {
    for (line1, line2, total, expected) in [
        ("0.1", "0.2", "0.30", 0),
        ("-1.005", "0", "-1.00", 0),
        ("-1.005", "0", "-1.01", 1),
        ("1", "2", "1", 1),
    ] {
        let body = format!(
            "<cac:LegalMonetaryTotal><cbc:LineExtensionAmount>{total}</cbc:LineExtensionAmount></cac:LegalMonetaryTotal><cac:InvoiceLine><cbc:LineExtensionAmount>{line1}</cbc:LineExtensionAmount></cac:InvoiceLine><cac:InvoiceLine><cbc:LineExtensionAmount>{line2}</cbc:LineExtensionAmount></cac:InvoiceLine>"
        );
        assert_eq!(findings(&run(&body), "BR-CO-10").len(), expected);
    }
}

#[test]
fn sdk_inclusive_total_uses_subtotals_and_accepts_multiple_matching_tax_totals() {
    let body = "<cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode><cac:TaxTotal><cbc:TaxAmount currencyID='SAR'>99</cbc:TaxAmount><cac:TaxSubtotal><cbc:TaxAmount>0.20</cbc:TaxAmount></cac:TaxSubtotal></cac:TaxTotal><cac:TaxTotal><cbc:TaxAmount currencyID='SAR'>0.20</cbc:TaxAmount></cac:TaxTotal><cac:LegalMonetaryTotal><cbc:TaxExclusiveAmount>0.1</cbc:TaxExclusiveAmount><cbc:TaxInclusiveAmount>0.3</cbc:TaxInclusiveAmount></cac:LegalMonetaryTotal>";
    let report = run(body);
    assert!(findings(&report, "BR-CO-15").is_empty());
    assert_eq!(findings(&report, "BR-CO-14").len(), 1);
    assert_eq!(
        findings(&run(&body.replace(">0.3<", ">0.31<")), "BR-CO-15").len(),
        1
    );
    assert!(
        findings(
            &run(&body
                .replace(
                    "<cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode>",
                    ""
                )
                .replace(">0.3<", ">0.31<")),
            "BR-CO-15"
        )
        .is_empty()
    );
    let missing = body.replace(" currencyID='SAR'", " currencyID='USD'");
    assert_eq!(findings(&run(&missing), "BR-CO-15").len(), 1);
}

#[test]
fn overlapping_patterns_both_execute_but_same_pattern_can_be_suppressed() {
    let report = run(
        "<cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode><cbc:TaxCurrencyCode>SAR</cbc:TaxCurrencyCode><cac:TaxTotal><cbc:TaxAmount currencyID='SAR'>0.000</cbc:TaxAmount></cac:TaxTotal><cac:LegalMonetaryTotal><cbc:TaxInclusiveAmount>0</cbc:TaxInclusiveAmount><cbc:TaxExclusiveAmount>0</cbc:TaxExclusiveAmount></cac:LegalMonetaryTotal>",
    );
    assert_eq!(findings(&report, "BR-DEC-13").len(), 1);
    assert_eq!(findings(&report, "BR-DEC-15").len(), 1);
    // cen:template:007 has no assertions, but suppresses the lower-priority
    // allowance template in the same d7e42 pattern for direct InvoiceLine nodes.
    let allowance = "<cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:Amount>1.000</cbc:Amount><cbc:BaseAmount>2.000</cbc:BaseAmount></cac:AllowanceCharge>";
    assert!(
        findings(
            &run(&format!("<cac:InvoiceLine>{allowance}</cac:InvoiceLine>")),
            "BR-DEC-24"
        )
        .is_empty()
    );
    let report = run(&format!(
        "<cac:CreditNoteLine>{allowance}</cac:CreditNoteLine>"
    ));
    assert_eq!(findings(&report, "BR-DEC-24").len(), 1);
    assert_eq!(findings(&report, "BR-DEC-25").len(), 1);
    assert_eq!(
        findings(
            &run(&format!(
                "<cac:Wrapper><cac:InvoiceLine>{allowance}</cac:InvoiceLine></cac:Wrapper>"
            )),
            "BR-DEC-24"
        )
        .len(),
        1
    );
}

#[test]
fn repeated_findings_keep_locations_and_general_comparison_semantics() {
    let report = run(
        "<cac:InvoiceLine><cac:Item><cbc:Name/></cac:Item></cac:InvoiceLine><cac:InvoiceLine><cac:Item><cbc:Name/></cac:Item></cac:InvoiceLine>",
    );
    let hits = findings(&report, "BR-25");
    assert_eq!(hits.len(), 2);
    assert_ne!(hits[0].location, hits[1].location);
    assert!(hits[0].location.ends_with("][1]"));
    assert!(hits[1].location.ends_with("][2]"));
    assert!(!report.has_errors());
    assert!(findings(&run("<cac:InvoiceLine><cac:Item><cbc:Name/><cbc:Name> </cbc:Name></cac:Item></cac:InvoiceLine>"), "BR-25").is_empty());
    let warning_json = serde_json::to_value(hits[0]).unwrap();
    assert_eq!(warning_json["severity"], "warning");
    assert_eq!(warning_json["site"], "cen:062:BR-25");
}

#[test]
fn evaluation_failure_preserves_findings_and_marks_subsequent_source_not_run() {
    let body = "<cac:LegalMonetaryTotal><cbc:LineExtensionAmount>1</cbc:LineExtensionAmount><cbc:PrepaidAmount>0</cbc:PrepaidAmount><cbc:PrepaidAmount>0</cbc:PrepaidAmount></cac:LegalMonetaryTotal>";
    let error = evaluate_slice(&invoice(body), &context()).unwrap_err();
    assert_eq!(error.failed_source, Some(Source::Cen));
    assert_eq!(error.report.stages[0].status, StageStatus::EvaluationFailed);
    assert_eq!(error.report.stages[1].status, StageStatus::NotRun);
    assert_eq!(findings(&error.report, "BR-CO-10").len(), 1);
    assert!(!error.report.is_complete());
    assert!(
        !error.report.stages[0]
            .evaluated_sites
            .contains(&"cen:028:BR-DEC-16")
    );
    assert!(error.location.is_some());
    let malformed = evaluate_slice("<broken>", &context()).unwrap_err();
    assert!(
        malformed
            .report
            .stages
            .iter()
            .all(|s| s.status == StageStatus::NotRun)
    );
    let invalid = body.replace(
        "<cbc:LineExtensionAmount>1</cbc:LineExtensionAmount>",
        "<cbc:LineExtensionAmount>NaN</cbc:LineExtensionAmount>",
    );
    assert_eq!(
        evaluate_slice(&invoice(&invalid), &context())
            .unwrap_err()
            .kind,
        FailureKind::InvalidDecimal
    );
    let mut limited = context();
    limited.limits.decimal_digits = 2;
    assert_eq!(evaluate_slice(&invoice("<cac:LegalMonetaryTotal><cbc:LineExtensionAmount>100</cbc:LineExtensionAmount></cac:LegalMonetaryTotal>"), &limited).unwrap_err().kind, FailureKind::Limit("decimal digits"));
}

fn fixture_root() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/business-rules"
    ))
}

#[test]
fn rule_metadata_matches_the_pinned_source_assertion_sites() {
    let bytes = std::fs::read(fixture_root().join("catalog.json")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        std::fs::read_to_string(fixture_root().join("catalog.sha256"))
            .unwrap()
            .trim()
    );
    let catalog: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(metadata::RULES.len(), 189);
    let coverage: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture_root().join("coverage.json")).unwrap(),
    )
    .unwrap();
    let implemented: std::collections::BTreeSet<_> = coverage["sites"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, value)| value["status"] == "implemented")
        .map(|(site, _)| site.as_str())
        .collect();
    assert_eq!(
        implemented,
        metadata::RULES.iter().map(|r| r.site).collect()
    );
    for rule in metadata::RULES {
        let source = catalog["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["source"] == rule.source.name())
            .unwrap();
        let site = source["assertions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["site"] == rule.site)
            .unwrap();
        assert_eq!(site["rule_id"], rule.code);
        assert_eq!(site["message"], rule.message);
        assert_eq!(
            site["severity"],
            serde_json::to_value(rule.severity).unwrap()
        );
    }
}

#[test]
fn frozen_sdk_mutations_match_implemented_rules_with_documented_occurrences() {
    assert_frozen_corpus("mutations", 24);
}

#[test]
fn frozen_sdk_identity_mutations_match_implemented_rules() {
    assert_frozen_corpus("identity", 46);
}

#[test]
fn frozen_sdk_structural_mutations_match_implemented_rules() {
    assert_frozen_corpus("structural", 57);
}

#[test]
fn frozen_sdk_monetary_mutations_match_implemented_rules() {
    assert_frozen_corpus("totals", 18);
}

#[test]
fn frozen_sdk_ksa_field_mutations_match_implemented_rules() {
    assert_frozen_corpus("ksa-fields", 22);
}

#[test]
fn frozen_sdk_buyer_mutations_match_implemented_rules() {
    assert_frozen_corpus("ksa-buyer", 34);
}

#[test]
fn frozen_sdk_document_mutations_match_implemented_rules() {
    assert_frozen_corpus("ksa-common", 21);
}

#[test]
fn frozen_sdk_vat_mutations_match_implemented_rules() {
    assert_frozen_corpus("vat", 22);
}

fn assert_frozen_corpus(family: &str, expected_cases: usize) {
    let corpus = fixture_root().join(family);
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(corpus.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["cases"].as_array().unwrap().len(), expected_cases);
    for (path, checksum) in manifest["artifacts"].as_object().unwrap() {
        let bytes = std::fs::read(corpus.join(path)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            checksum.as_str().unwrap(),
            "{path}"
        );
    }
    for case in manifest["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let directory = corpus.join("cases").join(id);
        let input = std::fs::read_to_string(directory.join("input.xml")).unwrap();
        let expected: Value = serde_json::from_str(
            &std::fs::read_to_string(directory.join("expected.json")).unwrap(),
        )
        .unwrap();
        // SDK transform failures discard the source's findings. They are not
        // evidence of a successful run with zero rule violations. Until this
        // internal slice is complete, compare only observable source results.
        let unavailable_sources: std::collections::BTreeSet<_> = expected["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["code"] == "SaxonApiException")
            .map(|f| f["source"].as_str().unwrap())
            .collect();
        let report =
            super::evaluate_slice(&input, &context()).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let mut observed = BTreeMap::new();
        let mut wanted = BTreeMap::new();
        for source in &report.stages {
            if unavailable_sources.contains(source.source.sdk_name()) {
                assert!(!report.is_complete());
                continue;
            }
            for f in &source.findings {
                *observed
                    .entry((
                        source.source.sdk_name().to_owned(),
                        f.code.to_owned(),
                        serde_json::to_value(f.severity)
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .to_owned(),
                        xml::normalize_space(f.message),
                    ))
                    .or_insert(0usize) += 1;
            }
        }
        for f in expected["findings"].as_array().unwrap() {
            if metadata::RULES
                .iter()
                .any(|r| r.source.sdk_name() == f["source"] && r.code == f["code"])
            {
                let count = if id == "repeated-empty-item-name"
                    && (f["code"] == "BR-25" || f["code"] == "BR-KSA-F-06-C19")
                {
                    2
                } else {
                    1
                };
                *wanted
                    .entry((
                        f["source"].as_str().unwrap().to_owned(),
                        f["code"].as_str().unwrap().to_owned(),
                        f["severity"].as_str().unwrap().to_owned(),
                        xml::normalize_space(f["message"].as_str().unwrap()),
                    ))
                    .or_insert(0usize) += count;
            }
        }
        assert_eq!(observed, wanted, "{id}");
        assert!(!report.is_complete());
    }
}

#[test]
fn partial_reports_preserve_finished_sources_and_bound_findings() {
    let mut bounded = context();
    bounded.limits.findings = 0;
    let error = evaluate_slice(
        &invoice("<cbc:TaxCurrencyCode>USD</cbc:TaxCurrencyCode>"),
        &bounded,
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Limit("findings"));
    assert_eq!(error.failed_source, Some(Source::Ksa));
    assert_eq!(error.report.stages[0].status, StageStatus::EvaluatedSubset);
    assert_eq!(error.report.stages[1].status, StageStatus::EvaluationFailed);
    assert_eq!(error.site, Some("ksa:136:BR-KSA-EN16931-02"));
    bounded.limits.findings = 1;
    let error =
        evaluate_slice(&invoice("<cac:InvoiceLine/><cac:InvoiceLine/>"), &bounded).unwrap_err();
    assert_eq!(findings(&error.report, "BR-25").len(), 1);
    assert!(
        !error.report.stages[0]
            .evaluated_sites
            .contains(&"cen:062:BR-25")
    );
    let json = serde_json::to_value(error.report).unwrap();
    assert_eq!(json["stages"][0]["status"], "evaluation_failed");
    assert_eq!(json["stages"][1]["status"], "not_run");
    let mut bounded = context();
    bounded.limits.finding_bytes = 1;
    let error = evaluate_slice(
        &invoice("<cbc:TaxCurrencyCode>USD</cbc:TaxCurrencyCode>"),
        &bounded,
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Limit("finding bytes"));
    assert!(error.report.stages[1].findings.is_empty());
}

#[test]
fn tax_currency_is_node_local_and_counts_only_sibling_bare_totals() {
    let body = "<cbc:TaxCurrencyCode>sar</cbc:TaxCurrencyCode><cbc:TaxCurrencyCode>USD</cbc:TaxCurrencyCode><cac:TaxTotal/><cac:TaxTotal><cac:TaxSubtotal/></cac:TaxTotal>";
    let report = run(body);
    assert_eq!(findings(&report, "BR-KSA-EN16931-02").len(), 1);
    assert!(findings(&report, "BR-KSA-EN16931-09").is_empty());
    assert_eq!(
        findings(
            &run(&body.replace("<cac:TaxTotal/>", "")),
            "BR-KSA-EN16931-09"
        )
        .len(),
        2
    );
    let nested = run(
        "<cac:Wrapper><cbc:TaxCurrencyCode>SAR</cbc:TaxCurrencyCode></cac:Wrapper><cac:TaxTotal/>",
    );
    assert_eq!(findings(&nested, "BR-KSA-EN16931-09").len(), 1);
    assert!(findings(&run(""), "BR-KSA-EN16931-09").is_empty());
    assert!(report.has_errors());
}

#[test]
fn allowance_contexts_keep_boolean_selection_and_empty_template_suppression() {
    for (indicator, expected) in [("false", 1), ("0", 1), ("true", 0), ("1", 0)] {
        let body = format!(
            "<cac:CreditNoteLine><cac:AllowanceCharge><cbc:ChargeIndicator>{indicator}</cbc:ChargeIndicator><cbc:Amount>1.000</cbc:Amount></cac:AllowanceCharge></cac:CreditNoteLine>"
        );
        assert_eq!(findings(&run(&body), "BR-DEC-24").len(), expected);
    }
    for amounts in [
        "",
        "<cbc:Amount/>",
        "<cbc:Amount>1.00</cbc:Amount><cbc:BaseAmount>2.00</cbc:BaseAmount>",
    ] {
        let report = run(&format!(
            "<cac:CreditNoteLine><cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator>{amounts}</cac:AllowanceCharge></cac:CreditNoteLine>"
        ));
        assert!(findings(&report, "BR-DEC-24").is_empty());
        assert!(findings(&report, "BR-DEC-25").is_empty());
    }
    let body = "<cac:CreditNoteLine><cac:AllowanceCharge><cbc:ChargeIndicator>invalid</cbc:ChargeIndicator></cac:AllowanceCharge></cac:CreditNoteLine>";
    assert_eq!(
        evaluate_slice(&invoice(body), &context()).unwrap_err().kind,
        FailureKind::InvalidBoolean
    );
    let body = "<cac:InvoiceLine><cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:Amount>0</cbc:Amount><cbc:Amount>1</cbc:Amount></cac:AllowanceCharge></cac:InvoiceLine>";
    // The empty winning template suppresses even the lower rule's cardinality error.
    assert!(evaluate_slice(&invoice(body), &context()).is_ok());
    assert_eq!(
        evaluate_slice(
            &invoice(&body.replace("InvoiceLine", "CreditNoteLine")),
            &context()
        )
        .unwrap_err()
        .kind,
        FailureKind::Cardinality
    );
    let credit = invoice(body)
        .replace("<Invoice ", "<CreditNote ")
        .replace("</Invoice>", "</CreditNote>")
        .replace(xml::UBL, xml::CREDIT_NOTE);
    assert!(evaluate_slice(&credit, &context()).is_ok());
    let mixed = "<cac:Wrapper><cac:InvoiceLine><cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:ChargeIndicator>true</cbc:ChargeIndicator><cbc:Amount>1.000</cbc:Amount></cac:AllowanceCharge></cac:InvoiceLine></cac:Wrapper>";
    assert!(findings(&run(mixed), "BR-DEC-24").is_empty());
    assert_eq!(
        findings(
            &run(&mixed.replace("InvoiceLine", "CreditNoteLine")),
            "BR-DEC-24"
        )
        .len(),
        1
    );
}

#[test]
fn tax_sum_rounding_missing_subtotals_and_duplicate_operands() {
    let report = run(
        "<cac:TaxTotal><cbc:TaxAmount>-1.00</cbc:TaxAmount><cac:TaxSubtotal><cbc:TaxAmount>-1.005</cbc:TaxAmount></cac:TaxSubtotal><cac:TaxSubtotal><cbc:TaxAmount>0</cbc:TaxAmount></cac:TaxSubtotal></cac:TaxTotal>",
    );
    assert!(findings(&report, "BR-CO-14").is_empty());
    assert!(findings(&run("<cac:TaxTotal/>"), "BR-CO-14").is_empty());
    assert_eq!(
        findings(
            &run("<cac:TaxTotal><cac:TaxSubtotal/></cac:TaxTotal>"),
            "BR-CO-14"
        )
        .len(),
        1
    );
    let body = "<cac:TaxTotal><cbc:TaxAmount>0</cbc:TaxAmount><cac:TaxSubtotal><cbc:TaxAmount>0</cbc:TaxAmount><cbc:TaxAmount>0</cbc:TaxAmount></cac:TaxSubtotal></cac:TaxTotal>";
    let error = evaluate_slice(&invoice(body), &context()).unwrap_err();
    assert_eq!(error.site, Some("cen:073:BR-CO-14"));
    assert_eq!(error.kind, FailureKind::Cardinality);
    let body = "<cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode><cac:TaxTotal><cbc:TaxAmount currencyID='SAR'>0</cbc:TaxAmount><cbc:TaxAmount currencyID='SAR'>0</cbc:TaxAmount></cac:TaxTotal>";
    let error = evaluate_slice(&invoice(body), &context()).unwrap_err();
    assert_eq!(error.site, Some("cen:048:BR-CO-15"));
    assert_eq!(error.kind, FailureKind::Cardinality);
}

#[test]
fn very_large_amounts_reach_native_rules_without_invoice_model_conversion() {
    let amount = "12345678901234567890123456789012345678901234567890";
    let report = run(&format!(
        "<cac:LegalMonetaryTotal><cbc:LineExtensionAmount>{amount}</cbc:LineExtensionAmount></cac:LegalMonetaryTotal><cac:InvoiceLine><cbc:LineExtensionAmount>{amount}</cbc:LineExtensionAmount></cac:InvoiceLine>"
    ));
    assert!(findings(&report, "BR-CO-10").is_empty());
    let report = run(
        "<cac:LegalMonetaryTotal><cbc:LineExtensionAmount>+1.</cbc:LineExtensionAmount></cac:LegalMonetaryTotal><cac:InvoiceLine><cbc:LineExtensionAmount>.5</cbc:LineExtensionAmount></cac:InvoiceLine><cac:CreditNoteLine><cbc:LineExtensionAmount>0.5</cbc:LineExtensionAmount></cac:CreditNoteLine>",
    );
    assert!(findings(&report, "BR-CO-10").is_empty());
}

#[test]
fn all_six_document_variants_match_the_frozen_observations_for_the_subset() {
    let original = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sdk-parity"
    ));
    let observations: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture_root().join("observations.json")).unwrap(),
    )
    .unwrap();
    for case in [
        "standard-invoice",
        "standard-credit",
        "standard-debit",
        "simplified-invoice",
        "simplified-credit",
        "simplified-debit",
    ] {
        let input =
            std::fs::read_to_string(original.join("cases").join(case).join("sdk-signed.xml"))
                .unwrap();
        let report = super::evaluate_slice(&input, &context()).unwrap();
        let expected = &observations["cases"][case]["signed-validate"]["report"]["findings"];
        let mut wanted = Vec::new();
        for finding in expected.as_array().unwrap() {
            if metadata::RULES
                .iter()
                .any(|r| r.source.sdk_name() == finding["source"] && r.code == finding["code"])
            {
                wanted.push((
                    finding["source"].as_str().unwrap().to_owned(),
                    finding["code"].as_str().unwrap().to_owned(),
                    finding["severity"].as_str().unwrap().to_owned(),
                    xml::normalize_space(finding["message"].as_str().unwrap()),
                ));
            }
        }
        let mut observed: Vec<_> = report
            .stages
            .iter()
            .flat_map(|stage| {
                stage.findings.iter().map(|f| {
                    (
                        stage.source.sdk_name().to_owned(),
                        f.code.to_owned(),
                        serde_json::to_value(f.severity)
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .to_owned(),
                        xml::normalize_space(f.message),
                    )
                })
            })
            .collect();
        wanted.sort();
        observed.sort();
        assert_eq!(observed, wanted, "{case}");
    }
}
