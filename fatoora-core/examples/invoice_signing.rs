// --8<-- [start:example]
pub fn main() {
    use fatoora_core::invoice::sign::invoice_hash_base64_from_xml_str;
    use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

    let signed_xml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
    let signed_xml = std::fs::read_to_string(&signed_xml_path).expect("read signed invoice xml");
    let signed = parse_signed_invoice_xml(&signed_xml).expect("parse signed invoice");

    let hash = invoice_hash_base64_from_xml_str(&signed_xml).expect("compute invoice hash");
    let qr = signed.qr_code();
    let signing_time = signed.signed_properties().signing_time();
    assert!(!hash.is_empty());
    assert!(!qr.is_empty());
    let _ = signing_time;
}
// --8<-- [end:example]
