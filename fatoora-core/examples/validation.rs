// --8<-- [start:example]
pub fn main() {
    use fatoora_core::config::{Config, EnvironmentType};
    use fatoora_core::invoice::validation::validate_xml_invoice_from_str;

    // Doc example: validate XML against the bundled schema.
    let invoice_xml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
    let config = Config::new(EnvironmentType::NonProduction);
    let xml = std::fs::read_to_string(&invoice_xml_path).expect("read invoice xml");
    validate_xml_invoice_from_str(&xml, &config).expect("validate invoice");
}
// --8<-- [end:example]
