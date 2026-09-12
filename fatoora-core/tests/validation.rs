mod common;

use fatoora_core::config::Config;
use fatoora_core::invoice::validation::{XmlValidationError, validate_xml_invoice_from_str};
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
fn test_validation_rejects_structurally_invalid_invoice() {
    let config = Config::default();
    let xml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
    let xml = std::fs::read_to_string(&xml_path).expect("read xml");

    // An element the UBL Invoice schema does not declare must be rejected;
    // this is what proves the imported CBC/CAC schemas actually loaded.
    let tampered = xml.replace("<cbc:ID>", "<cbc:NotARealUblElement/><cbc:ID>");
    assert_ne!(
        tampered, xml,
        "fixture did not contain the expected element"
    );

    match validate_xml_invoice_from_str(&tampered, &config) {
        Ok(()) => panic!("expected schema validation to reject the tampered invoice"),
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains("schema validation error"),
                "unexpected error: {message}"
            );
        }
    }
}

#[test]
fn test_validation_rejects_malformed_xml() {
    let config = Config::default();
    let result = validate_xml_invoice_from_str("<Invoice><unclosed>", &config);
    // Asserting the variant, not just `is_err`: the schema is built before the
    // XML is parsed, so a plain `is_err` would also pass if the schema failed
    // to compile and the malformed XML were never looked at.
    match result {
        Err(XmlValidationError::XmlParse { .. }) => (),
        Ok(()) => panic!("expected malformed XML to be rejected"),
        Err(other) => panic!("expected an XML parse error, got: {other}"),
    }
}

fn replace_element_text(xml: &str, name: &str, value: &str) -> String {
    let start = xml.find(&format!("<{name}")).expect("fixture element");
    let text_start = start + xml[start..].find('>').unwrap() + 1;
    let text_end = text_start + xml[text_start..].find(&format!("</{name}>")).unwrap();
    format!("{}{value}{}", &xml[..text_start], &xml[text_end..])
}

#[test]
fn validation_rejects_invalid_inherited_simple_content() {
    let xml = include_str!("fixtures/invoices/sample-simplified-invoice.xml");
    for (element, value) in [
        ("cbc:IssueDate", "not-a-date"),
        ("cbc:IssueDate", "2024-02-30"),
        ("cbc:IssueTime", "25:00:00"),
        ("cbc:TaxAmount", "garbage"),
        ("cbc:TaxAmount", "1e3"),
        ("cbc:InvoicedQuantity", "garbage"),
    ] {
        let tampered = replace_element_text(xml, element, value);
        assert!(
            matches!(
                validate_xml_invoice_from_str(&tampered, &Config::default()),
                Err(XmlValidationError::SchemaValidation { errors }) if !errors.is_empty()
            ),
            "accepted {element}={value}"
        );
    }
}

#[test]
fn validation_rejects_child_elements_in_simple_content() {
    let xml = include_str!("fixtures/invoices/sample-simplified-invoice.xml");
    for (element, value) in [
        ("cbc:ID", "<unexpected/>123"),
        ("cbc:TaxAmount", "<unexpected/>10.00"),
        ("cbc:IssueDate", "<unexpected/>2024-01-01"),
    ] {
        let tampered = replace_element_text(xml, element, value);
        assert!(
            matches!(
                validate_xml_invoice_from_str(&tampered, &Config::default()),
                Err(XmlValidationError::SchemaValidation { errors }) if !errors.is_empty()
            ),
            "accepted child element in {element}"
        );
    }
}

#[test]
fn validation_accepts_valid_inherited_simple_content() {
    let xml = include_str!("fixtures/invoices/sample-simplified-invoice.xml");
    for (element, value) in [
        ("cbc:IssueDate", "2024-02-29"),
        ("cbc:IssueTime", "23:59:59"),
        ("cbc:TaxAmount", "-10.25"),
        ("cbc:InvoicedQuantity", "0.125"),
        ("cbc:ID", "A&amp;B"),
    ] {
        let modified = replace_element_text(xml, element, value);
        validate_xml_invoice_from_str(&modified, &Config::default())
            .unwrap_or_else(|error| panic!("rejected {element}={value}: {error:?}"));
    }
}
