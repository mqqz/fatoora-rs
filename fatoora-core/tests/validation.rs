mod common;

use fatoora_core::config::Config;
use fatoora_core::invoice::validation::validate_xml_invoice_from_str;
use fatoora_core::invoice::xml::ToXml;

#[test]
fn test_validate_xml_invoice() {
    let config = Config::default();
    let xml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
    let xml = std::fs::read_to_string(&xml_path).expect("read xml");
    let result = validate_xml_invoice_from_str(&xml, &config);
    match result {
        Ok(_) => (),
        Err(error) => panic!("XML validation failed: {error}"),
    }
}

#[test]
fn test_our_invoices_can_be_validated() {
    let config = Config::default();
    let xml_invoice = common::dummy_finalized_invoice()
        .to_xml()
        .expect("failed to serialize dummy invoice");
    let result = validate_xml_invoice_from_str(&xml_invoice, &config);
    match result {
        Ok(_) => (),
        Err(error) => panic!("XML validation failed: {error}"),
    }
}

#[test]
fn reports_only_completed_xsd_checks() {
    use fatoora_core::invoice::validation::{
        ValidationLayer, validate_xml_invoice_report_from_str,
    };
    let xml = common::dummy_finalized_invoice().to_xml().unwrap();
    let report = validate_xml_invoice_report_from_str(&xml, &Config::default()).unwrap();
    assert_eq!(report.layers_checked, vec![ValidationLayer::Xsd]);
    assert!(report.issues.is_empty());
    assert!(!report.has_errors());
}

#[test]
fn schema_violations_are_findings_but_malformed_xml_is_an_error() {
    use fatoora_core::invoice::validation::{
        Severity, ValidationLayer, XmlValidationError, validate_xml_invoice_report_from_str,
    };
    let config = Config::default();
    let report = validate_xml_invoice_report_from_str("<not-an-invoice/>", &config).unwrap();
    assert_eq!(report.layers_checked, vec![ValidationLayer::Xsd]);
    assert!(report.has_errors());
    assert!(
        report.issues.iter().any(|finding| {
            finding.code == "XSD_INVALID" && finding.severity == Severity::Error
        })
    );
    assert!(matches!(
        validate_xml_invoice_from_str("<not-an-invoice/>", &config),
        Err(XmlValidationError::SchemaValidation { .. })
    ));
    assert!(matches!(
        validate_xml_invoice_report_from_str("<", &config),
        Err(XmlValidationError::XmlParse { .. })
    ));
    // Recovery could otherwise repair this into a schema-valid invoice.
    let xml = common::dummy_finalized_invoice().to_xml().unwrap();
    let malformed = xml.replacen("</Invoice>", "", 1);
    assert_ne!(malformed, xml);
    assert!(matches!(
        validate_xml_invoice_from_str(&malformed, &config),
        Err(XmlValidationError::XmlParse { .. })
    ));
}

#[test]
fn builder_errors_convert_to_field_findings() {
    use fatoora_core::invoice::validation::{
        ValidationLayer, ValidationLocation, ValidationReport,
    };
    use fatoora_core::invoice::{InvoiceBuilder, InvoiceError, InvoiceSubType, InvoiceType};

    let error = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified))
        .build()
        .unwrap_err();
    let InvoiceError::Validation(error) = error else {
        panic!("expected field errors")
    };
    let report = ValidationReport::from(&error);
    assert_eq!(report.layers_checked, vec![ValidationLayer::FieldChecks]);
    assert!(report.has_errors());
    assert_eq!(report.issues.len(), error.issues().len());
    assert!(report.issues.iter().any(|finding| {
        finding.code == "FIELD_REQUIRED"
            && finding.location == Some(ValidationLocation::Field("id".to_owned()))
    }));
}

#[test]
fn report_preserves_indexed_locations_and_warning_semantics() {
    use fatoora_core::invoice::validation::{
        Severity, ValidationFinding, ValidationLayer, ValidationLocation, ValidationReport,
    };
    use fatoora_core::invoice::{InvoiceField, ValidationIssue, ValidationKind};
    let issue = ValidationIssue::new(
        InvoiceField::LineItemQuantity,
        ValidationKind::OutOfRange,
        Some(2),
    );
    let mut finding = ValidationFinding::from(&issue);
    assert_eq!(finding.code, "FIELD_OUT_OF_RANGE");
    assert_eq!(
        finding.location,
        Some(ValidationLocation::Field("line_items[2].quantity".into()))
    );
    finding.severity = Severity::Warning;
    let report = ValidationReport {
        layers_checked: vec![ValidationLayer::FieldChecks],
        issues: vec![finding],
    };
    assert!(!report.has_errors());
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["layers_checked"], serde_json::json!(["field_checks"]));
    assert_eq!(json["issues"][0]["severity"], "warning");
    assert_eq!(
        serde_json::from_value::<ValidationReport>(json).unwrap(),
        report
    );
}
