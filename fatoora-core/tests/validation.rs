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
