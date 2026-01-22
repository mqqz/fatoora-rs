// --8<-- [start:example]
pub fn main() {
    use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

    // Doc example: extract QR payload from signed XML.
    let signed_xml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
    let signed_xml = std::fs::read_to_string(&signed_xml_path).expect("read signed invoice xml");
    let signed = parse_signed_invoice_xml(&signed_xml).expect("parse signed invoice");
    let qr = signed.qr_code();
    assert!(!qr.is_empty());
}
// --8<-- [end:example]
