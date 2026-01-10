mod common;

use fatoora_core::config::Config;
use fatoora_core::invoice::validation::{
    validate_xml_invoice_from_file, validate_xml_invoice_from_str,
};
use fatoora_core::invoice::xml::ToXml;
use std::path::Path;

#[test]
fn test_validate_xml_invoice() {
    let config = Config::default();
    let xml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
    let result = validate_xml_invoice_from_file(&xml_path, &config);
    match result {
        Ok(_) => (),
        Err(errors) => {
            for error in errors {
                println!("Validation error: {}", error);
            }
            panic!("XML validation failed");
        }
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
        Err(errors) => {
            for error in errors {
                println!("Validation error: {}", error);
            }
            panic!("XML validation failed");
        }
    }
}
