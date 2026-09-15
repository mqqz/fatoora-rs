use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

#[test]
fn into_xml_moves_exact_imported_xml() {
    let xml = include_str!("fixtures/invoices/sample-simplified-invoice.xml");
    let signed = parse_signed_invoice_xml(xml).unwrap();
    assert_eq!(signed.xml(), xml);
    let ptr = signed.xml().as_ptr();
    let owned = signed.into_xml();
    assert_eq!(owned, xml);
    assert_eq!(owned.as_ptr(), ptr);
}
