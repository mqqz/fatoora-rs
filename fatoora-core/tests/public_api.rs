//! Supported consumer workflows; no XML implementation traits are imported.
mod common;

use base64ct::{Base64, Encoding};
use fatoora_core::config::Config;
use fatoora_core::invoice::sign::{InvoiceSigner, invoice_hash_base64_from_xml_str};
use fatoora_core::invoice::validation::{
    ValidationLayer, XmlValidationError, validate_xml_invoice_report_from_str,
};
use fatoora_core::invoice::xml::{
    InvoiceXmlError, XmlFormat,
    parse::{parse_finalized_invoice_xml, parse_signed_invoice_xml},
};
use fatoora_core::invoice::{
    FinalizedInvoice, InvoiceBuilder, InvoiceError, InvoiceSubType, InvoiceType,
};
use fatoora_core::{Decimal, ErrorKind};

#[test]
fn construction_import_signing_and_validation_use_direct_methods() {
    // Taking method pointers ensures these are inherent, publicly callable methods.
    let serialize: fn(&FinalizedInvoice) -> Result<String, InvoiceXmlError> =
        FinalizedInvoice::to_xml;
    let invoice = common::dummy_finalized_invoice();
    assert_eq!(invoice.totals().tax_amount(), Decimal::parse("15").unwrap());
    assert_eq!(
        invoice.totals().payable_amount(),
        Decimal::parse("115").unwrap()
    );
    let xml = serialize(&invoice).unwrap();
    let compact = invoice.to_xml_with_format(XmlFormat::Compact).unwrap();
    let imported = parse_finalized_invoice_xml(&xml).unwrap();
    assert_eq!(parse_finalized_invoice_xml(&compact).unwrap(), imported);
    assert_eq!(imported.data().id(), invoice.data().id());
    assert_eq!(imported.data().line_items(), invoice.data().line_items());
    assert_eq!(imported.totals(), invoice.totals());
    let report = validate_xml_invoice_report_from_str(&xml, &Config::default()).unwrap();
    assert_eq!(report.layers_checked, [ValidationLayer::Xsd]);
    assert!(!report.has_errors());

    let cert =
        Base64::decode_vec(include_str!("fixtures/certs/zatca_cert_b64.txt").trim()).unwrap();
    let cert = Base64::decode_vec(std::str::from_utf8(&cert).unwrap().trim()).unwrap();
    let key = include_bytes!("fixtures/pkeys/test_zatca_pkey.der");
    let signer = InvoiceSigner::from_der(&cert, key).unwrap();
    let signed = invoice.sign(&signer).unwrap();
    assert_eq!(signed.data().id(), "INV-1");
    assert_eq!(
        signed.totals().payable_amount(),
        Decimal::parse("115").unwrap()
    );
    assert_eq!(
        signed.invoice_hash(),
        invoice_hash_base64_from_xml_str(signed.xml()).unwrap()
    );
    let imported = parse_signed_invoice_xml(signed.xml()).unwrap();
    assert_eq!(imported.into_xml(), signed.xml());
    let raw_signed = signer.sign_xml(&xml).unwrap();
    assert_eq!(
        parse_signed_invoice_xml(&raw_signed).unwrap().into_xml(),
        raw_signed
    );
}

#[test]
fn consumer_can_inspect_failures_without_backend_types() {
    let error: InvoiceError = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified))
        .build()
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Validation);
    let InvoiceError::Validation(fields) = error else {
        panic!("expected field errors")
    };
    assert!(!fields.issues().is_empty());
    assert!(matches!(
        validate_xml_invoice_report_from_str("<", &Config::default()),
        Err(XmlValidationError::XmlParse { .. })
    ));
    let report = validate_xml_invoice_report_from_str("<wrong/>", &Config::default()).unwrap();
    assert!(report.has_errors());
    assert_eq!(report.layers_checked, [ValidationLayer::Xsd]);
}

#[test]
fn implementation_details_are_not_extension_points() {
    trybuild::TestCases::new().compile_fail("tests/ui/public_api/*.rs");
}
