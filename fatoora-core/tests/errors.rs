use std::error::Error as StdError;

use fatoora_core::api::{ServerErrorResponse, ZatcaError};
use fatoora_core::config::Config;
use fatoora_core::csr::{Csr, CsrError, CsrProperties};
use fatoora_core::invoice::sign::SigningError;
use fatoora_core::invoice::validation::{XmlValidationError, validate_xml_invoice_from_str};
use fatoora_core::invoice::{InvoiceError, InvoiceField, LineItem, VatCategory};
use fatoora_core::{Decimal, Diagnostic, Error, ErrorKind};
use serde_json::{Value, json};

fn decimal(value: &str) -> Decimal {
    Decimal::parse(value).unwrap()
}

#[test]
fn wrapping_retains_validation_fields_and_exact_amounts() {
    let original = LineItem::try_from_parts(
        "item",
        decimal("1"),
        "PCE",
        decimal("100"),
        decimal("100"),
        decimal("15"),
        decimal("10"),
        VatCategory::Standard,
    )
    .unwrap_err();
    let error: Error = original.into();
    assert_eq!(error.kind(), ErrorKind::Validation);
    let Error::Invoice(InvoiceError::Validation(validation)) = &error else {
        panic!("lost module error: {error}");
    };
    let issue = &validation.issues()[0];
    assert_eq!(issue.field(), InvoiceField::LineItemVatAmount);
    assert_eq!(issue.supplied(), Some(decimal("10")));
    assert_eq!(issue.expected(), Some(decimal("15")));
    assert!(error.source().unwrap().is::<InvoiceError>());
    let details: Value = serde_json::from_str(&error.details_json()).unwrap();
    assert_eq!(
        details,
        json!({"type": "invoice_validation", "issues": [{
            "field": "line_item_vat_amount", "kind": "mismatch", "line_item_index": null,
            "supplied": "10", "expected": "15"
        }]})
    );
}

#[test]
fn nested_signing_error_retains_validation_details() {
    let invoice_error =
        InvoiceError::Validation(fatoora_core::invoice::ValidationError::new(vec![
            fatoora_core::invoice::ValidationIssue::new(
                InvoiceField::LineItemDescription,
                fatoora_core::invoice::ValidationKind::Empty,
                Some(2),
            ),
        ]));
    let error: Error = SigningError::from(invoice_error).into();
    assert_eq!(error.kind(), ErrorKind::Validation);
    let details: Value = serde_json::from_str(&error.details_json()).unwrap();
    assert_eq!(details["type"], "invoice_validation");
    assert_eq!(details["issues"][0]["line_item_index"], 2);
}

#[test]
fn schema_diagnostics_survive_conversion() {
    let error: Error = validate_xml_invoice_from_str("<Invoice/>\n", &Config::default())
        .unwrap_err()
        .into();
    assert_eq!(error.kind(), ErrorKind::Validation);
    let Error::XmlValidation(XmlValidationError::SchemaValidation { errors }) = &error else {
        panic!("expected schema diagnostics: {error}");
    };
    assert!(!errors.is_empty());
    assert!(!errors[0].message().is_empty());
    assert!(errors[0].source().is_none());
    let details: Value = serde_json::from_str(&error.details_json()).unwrap();
    assert_eq!(details["type"], "schema_validation");
    assert_eq!(details["diagnostics"][0]["message"], errors[0].message());
    assert_eq!(details["diagnostics"][0]["line"], json!(errors[0].line()));
}

#[test]
fn csr_backend_sources_are_owned_diagnostics() {
    let error: Error = Csr::from_der(b"not DER").unwrap_err().into();
    let csr = error.source().unwrap();
    assert!(csr.is::<CsrError>());
    let diagnostic = csr.source().unwrap().downcast_ref::<Diagnostic>().unwrap();
    assert!(!diagnostic.message().is_empty());
    assert!(diagnostic.source().is_none());

    let error = CsrProperties::from_properties_str("name=\\uZZZZ").unwrap_err();
    let CsrError::PropertiesRead { source, .. } = error else {
        panic!("expected properties parse failure");
    };
    assert_eq!(source.line(), Some(1));
    assert!(source.source().is_none());
}

#[test]
fn api_response_fields_survive_and_json_escapes_diagnostics() {
    let response: ServerErrorResponse = serde_json::from_value(json!({
        "category": "validation", "code": "BR-01", "message": "خطأ\u{0}\n\"quoted\""
    }))
    .unwrap();
    let error: Error = ZatcaError::ServerError(response).into();
    let details: Value = serde_json::from_str(&error.details_json()).unwrap();
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(details["response"]["code"], "BR-01");
    assert_eq!(details["response"]["message"], "خطأ\u{0}\n\"quoted\"");
}

#[test]
fn unreadable_file_keeps_io_classification_and_path() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/nonexistent-issue-9/invoice.xml");
    let error: Error = fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml_file(&path)
        .unwrap_err()
        .into();
    assert_eq!(error.kind(), ErrorKind::Io);
    let details: Value = serde_json::from_str(&error.details_json()).unwrap();
    assert_eq!(details["type"], "io");
    assert_eq!(details["path"], path.to_string_lossy().as_ref());
}
