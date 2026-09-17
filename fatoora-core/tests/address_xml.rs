mod common;

use fatoora_core::config::Config;
use fatoora_core::invoice::validation::validate_xml_invoice_from_str;
use fatoora_core::invoice::xml::parse::{parse_finalized_invoice_xml, parse_signed_invoice_xml};

#[test]
fn imports_optional_seller_address_fields_from_xml() {
    let original = include_str!("fixtures/invoices/sample-simplified-invoice.xml");
    let absent = parse_finalized_invoice_xml(original).unwrap();
    assert_eq!(absent.data().seller().address().additional_street(), None);
    assert_eq!(absent.data().seller().address().additional_number(), None);
    // Independent XML input, rather than relying on our serializer's field mapping.
    let xml = original
        .replacen(
            "</cbc:StreetName>",
            "</cbc:StreetName><cbc:AdditionalStreetName>Second street</cbc:AdditionalStreetName>",
            1,
        )
        .replacen(
            "</cbc:BuildingNumber>",
            "</cbc:BuildingNumber><cbc:PlotIdentification>0123</cbc:PlotIdentification>",
            1,
        );
    let invoice = parse_finalized_invoice_xml(&xml).unwrap();
    let address = invoice.data().seller().address();
    assert_eq!(address.additional_street(), Some("Second street"));
    assert_eq!(address.additional_number(), Some("0123"));
    assert_eq!(address.district(), Some("المربع | Al-Murabba"));
    let signed = parse_signed_invoice_xml(&xml).unwrap();
    assert_eq!(signed.data().seller().address(), address);
    assert_eq!(signed.xml(), xml);
}

#[test]
fn serializes_and_imports_additional_number() {
    let invoice = common::dummy_finalized_invoice();
    let xml = invoice.to_xml().unwrap();
    assert!(xml.contains("<cbc:PlotIdentification>5678</cbc:PlotIdentification>"));
    assert!(xml.contains("<cbc:CitySubdivisionName>Olaya</cbc:CitySubdivisionName>"));
    validate_xml_invoice_from_str(&xml, &Config::default()).unwrap();
    let imported = parse_finalized_invoice_xml(&xml).unwrap();
    assert_eq!(
        imported.data().seller().address().additional_number(),
        Some("5678")
    );
    assert_eq!(
        imported.data().seller().address(),
        invoice.data().seller().address()
    );
}
