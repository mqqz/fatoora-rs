//! Mutate one field of an accepted fixture so rejection cannot be caused by an
//! unrelated missing field. Parsing checks supplied amounts; it is not validation.
use base64ct::{Base64, Encoding};
use fatoora_core::invoice::xml::parse::{parse_finalized_invoice_xml, parse_signed_invoice_xml};
use fatoora_core::{Error, ErrorKind};
use libxml::{parser::Parser, xpath::Context};
use serde_json::Value;

const XML: &str = include_str!("fixtures/invoices/sample-simplified-invoice.xml");
const ROOT: &str = "/ubl:Invoice";
const LINE: &str = "/ubl:Invoice/cac:InvoiceLine[1]";

fn change(xml: &str, path: &str, value: &str) -> String {
    let doc = Parser::default().parse_string(xml).unwrap();
    let ctx = Context::new(&doc).unwrap();
    for (prefix, namespace) in [
        (
            "ubl",
            "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
        ),
        (
            "cac",
            "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
        ),
        (
            "cbc",
            "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
        ),
    ] {
        ctx.register_namespace(prefix, namespace).unwrap();
    }
    let mut nodes = ctx.evaluate(path).unwrap().get_nodes_as_vec();
    assert_eq!(nodes.len(), 1, "mutation must target one field: {path}");
    nodes[0].set_content(value).unwrap();
    doc.to_string()
}

fn invalid(xml: &str, field: &str) {
    let error: Error = parse_finalized_invoice_xml(xml).unwrap_err().into();
    assert_eq!(error.kind(), ErrorKind::InvalidInput, "{field}: {error}");
    let details: Value = serde_json::from_str(&error.details_json()).unwrap();
    assert_eq!(details["type"], "invalid_value", "{field}: {details}");
    assert_eq!(details["field"], field, "{details}");
}

#[test]
fn malformed_line_numbers_report_the_specific_field() {
    parse_finalized_invoice_xml(XML).unwrap();
    for (path, field) in [
        ("cbc:InvoicedQuantity", "InvoicedQuantity"),
        ("cac:Price/cbc:PriceAmount", "PriceAmount"),
        ("cbc:LineExtensionAmount", "LineExtensionAmount"),
        (
            "cac:Item/cac:ClassifiedTaxCategory/cbc:Percent",
            "LineVatPercent",
        ),
        ("cac:TaxTotal/cbc:TaxAmount", "LineTaxAmount"),
    ] {
        for value in ["NaN", "1,00", "79228162514264337593543950336"] {
            invalid(&change(XML, &format!("{LINE}/{path}"), value), field);
        }
    }
}

#[test]
fn line_precision_and_gross_checks_reject_one_cent_and_subcent_changes() {
    for (path, value, field) in [
        ("cbc:LineExtensionAmount", "99.001", "LineItem"),
        ("cac:TaxTotal/cbc:TaxAmount", "14.851", "LineItem"),
        ("cbc:LineExtensionAmount", "99.01", "LineExtensionAmount"),
        (
            "cac:TaxTotal/cbc:RoundingAmount",
            "113.86",
            "LineGrossAmount",
        ),
    ] {
        invalid(&change(XML, &format!("{LINE}/{path}"), value), field);
    }
}

#[test]
fn adjustment_inputs_cannot_be_silently_coerced() {
    for (path, value, field) in [
        ("cbc:ChargeIndicator", "yes", "ChargeIndicator"),
        ("cbc:Amount", "-0.01", "AdjustmentAmount"),
        ("cbc:Amount", "0.001", "AdjustmentAmount"),
        ("cbc:Amount", "NaN", "AdjustmentAmount"),
        (
            "cac:TaxCategory[1]/cbc:ID",
            "UNKNOWN",
            "AdjustmentVatCategory",
        ),
        ("cac:TaxCategory[1]/cbc:Percent", "NaN", "AdjustmentVatRate"),
    ] {
        invalid(
            &change(XML, &format!("{ROOT}/cac:AllowanceCharge[1]/{path}"), value),
            field,
        );
    }
    // Both XML boolean spellings must have the same financial meaning.
    for value in ["false", "0", "true", "1"] {
        let parsed = parse_finalized_invoice_xml(&change(
            XML,
            &format!("{ROOT}/cac:AllowanceCharge[1]/cbc:ChargeIndicator"),
            value,
        ))
        .unwrap();
        assert_eq!(parsed.totals().payable_amount().to_string(), "231.15");
    }
}

#[test]
fn tax_subtotals_reject_unknown_and_duplicate_groups() {
    let path = format!("{ROOT}/cac:TaxTotal/cac:TaxSubtotal/cac:TaxCategory/cbc:Percent");
    invalid(&change(XML, &path, "14"), "TaxSubtotal");
    let start = XML.find("<cac:TaxSubtotal>").unwrap();
    let end = XML[start..].find("</cac:TaxSubtotal>").unwrap() + start + "</cac:TaxSubtotal>".len();
    let duplicated = format!("{}{}{}", &XML[..end], &XML[start..end], &XML[end..]);
    invalid(&duplicated, "TaxSubtotal");
}

#[test]
fn prepaid_and_rounding_values_preserve_the_payable_equation() {
    let with_amounts = XML.replace("</cac:LegalMonetaryTotal>", "<cbc:PayableRoundingAmount currencyID=\"SAR\">-0.01</cbc:PayableRoundingAmount></cac:LegalMonetaryTotal>");
    let with_amounts = change(
        &with_amounts,
        &format!("{ROOT}/cac:LegalMonetaryTotal/cbc:PrepaidAmount"),
        "31.15",
    );
    let xml = change(
        &with_amounts,
        &format!("{ROOT}/cac:LegalMonetaryTotal/cbc:PayableAmount"),
        "199.99",
    );
    let invoice = parse_finalized_invoice_xml(&xml).unwrap();
    assert_eq!(invoice.totals().prepaid_amount().to_string(), "31.15");
    assert_eq!(
        invoice.totals().payable_rounding_amount().to_string(),
        "-0.01"
    );
    assert_eq!(invoice.totals().payable_amount().to_string(), "199.99");
    for (field, value) in [
        ("PrepaidAmount", "-0.01"),
        ("PrepaidAmount", "31.151"),
        ("PayableRoundingAmount", "0.001"),
        ("PayableAmount", "200.00"),
    ] {
        invalid(
            &change(
                &xml,
                &format!("{ROOT}/cac:LegalMonetaryTotal/cbc:{field}"),
                value,
            ),
            field,
        );
    }
}

#[test]
fn malformed_dates_and_counters_are_not_normalized() {
    for (path, value, field) in [
        ("cbc:IssueDate", "2024-02-30", "IssueDateTime"),
        ("cbc:IssueTime", "24:01:00", "IssueTime"),
        (
            "cac:AdditionalDocumentReference[cbc:ID='ICV']/cbc:UUID",
            "-1",
            "ICV",
        ),
        (
            "cac:AdditionalDocumentReference[cbc:ID='ICV']/cbc:UUID",
            "18446744073709551616",
            "ICV",
        ),
    ] {
        invalid(&change(XML, &format!("{ROOT}/{path}"), value), field);
    }
}

#[test]
fn signed_parser_rejects_incomplete_or_ambiguous_qr_tlv() {
    let doc = Parser::default().parse_string(XML).unwrap();
    let ctx = Context::new(&doc).unwrap();
    let qr_path = "//*[local-name()='AdditionalDocumentReference'][*[local-name()='ID']='QR']//*[local-name()='EmbeddedDocumentBinaryObject']";
    let qr = ctx.evaluate(qr_path).unwrap().get_nodes_as_vec()[0].get_content();
    let raw = Base64::decode_vec(&qr).unwrap();
    let mut trailing_header = raw.clone();
    trailing_header.push(10);
    let mut truncated_value = raw.clone();
    truncated_value.extend([10, 2, 1]);
    let mut duplicate_hash = raw;
    duplicate_hash.extend([6, 1, b'x']);
    for value in [
        "%%%".to_owned(),
        Base64::encode_string(&trailing_header),
        Base64::encode_string(&truncated_value),
        Base64::encode_string(&duplicate_hash),
    ] {
        let xml = change(XML, qr_path, &value);
        let error: Error = parse_signed_invoice_xml(&xml)
            .expect_err("malformed QR must be rejected")
            .into();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let details: Value = serde_json::from_str(&error.details_json()).unwrap();
        assert_eq!(details["field"], "QR");
    }
}

#[test]
fn imported_transaction_flags_survive_serialization() {
    // The five digits follow the subtype in wire order: third party, nominal,
    // export, summary, self billed. Exercise each bit and their combinations.
    for bits in 0u8..32 {
        let digits: String = (0..5)
            .map(|bit| if bits & (1 << bit) == 0 { '0' } else { '1' })
            .collect();
        for subtype in ["01", "02"] {
            let code = format!("{subtype}{digits}");
            let xml = change(XML, &format!("{ROOT}/cbc:InvoiceTypeCode/@name"), &code);
            let invoice = parse_finalized_invoice_xml(&xml).unwrap();
            assert_eq!(invoice.data().flags().bits(), bits, "wire code {code}");
            assert_eq!(
                invoice.data().invoice_type().is_simplified(),
                subtype == "02"
            );
            assert!(
                invoice
                    .to_xml()
                    .unwrap()
                    .contains(&format!("name=\"{code}\""))
            );
        }
    }
    for code in ["02", "02000000", "02000x0", "0200020", "0300000", "02é000"] {
        invalid(
            &change(XML, &format!("{ROOT}/cbc:InvoiceTypeCode/@name"), code),
            "InvoiceTypeCode@name",
        );
    }
}

#[test]
fn signed_parser_requires_each_qr_signature_component() {
    use fatoora_core::invoice::xml::parse::ParseError;
    let doc = Parser::default().parse_string(XML).unwrap();
    let ctx = Context::new(&doc).unwrap();
    let path = "//*[local-name()='AdditionalDocumentReference'][*[local-name()='ID']='QR']//*[local-name()='EmbeddedDocumentBinaryObject']";
    let raw = Base64::decode_vec(&ctx.evaluate(path).unwrap().get_nodes_as_vec()[0].get_content())
        .unwrap();
    for (missing, label) in [
        (6, "QR tag 6 (invoice hash)"),
        (7, "QR tag 7 (signature)"),
        (8, "QR tag 8 (public key)"),
    ] {
        let mut without_tag = Vec::new();
        let mut offset = 0;
        while offset < raw.len() {
            let end = offset + 2 + usize::from(raw[offset + 1]);
            if raw[offset] != missing {
                without_tag.extend_from_slice(&raw[offset..end]);
            }
            offset = end;
        }
        let xml = change(XML, path, &Base64::encode_string(&without_tag));
        assert!(
            matches!(parse_signed_invoice_xml(&xml), Err(ParseError::MissingField(field)) if field == label)
        );
    }
    // Tags 6 and 7 carry UTF-8 text, unlike the binary public key in tag 8.
    for (tag, label) in [(6, "QR tag 6 (invoice hash)"), (7, "QR tag 7 (signature)")] {
        let mut corrupted = raw.clone();
        let mut offset = 0;
        while corrupted[offset] != tag {
            offset += 2 + usize::from(corrupted[offset + 1]);
        }
        corrupted[offset + 2] = 0xff;
        let xml = change(XML, path, &Base64::encode_string(&corrupted));
        assert!(
            matches!(parse_signed_invoice_xml(&xml), Err(ParseError::MissingField(field)) if field == label)
        );
    }
}

#[test]
fn imported_note_preserves_language_text_and_default_language() {
    let text = "خصم & تسوية <فاتورة>";
    let xml = XML.replace(
        ">ABC</cbc:Note>",
        ">خصم &amp; تسوية &lt;فاتورة&gt;</cbc:Note>",
    );
    for (xml, language) in [
        (xml.clone(), "ar"),
        (xml.replace(" languageID=\"ar\"", ""), "en"),
    ] {
        let invoice = parse_finalized_invoice_xml(&xml).unwrap();
        let note = invoice.data().note().unwrap();
        assert_eq!(note.text(), text);
        assert_eq!(note.language(), language);
        let serialized = invoice.to_xml().unwrap();
        let reparsed = parse_finalized_invoice_xml(&serialized).unwrap();
        assert_eq!(reparsed.data().note(), invoice.data().note());
    }
}

#[test]
fn adjustment_vat_groups_cannot_be_merged_or_reassigned() {
    // Even zero-value adjustments must refer to a group that actually exists.
    invalid(
        &change(
            XML,
            &format!("{ROOT}/cac:AllowanceCharge[1]/cac:TaxCategory[1]/cbc:Percent"),
            "5",
        ),
        "AdjustmentVatRate",
    );
    let start = XML.find("<cac:AllowanceCharge>").unwrap();
    let end = XML[start..].find("</cac:AllowanceCharge>").unwrap()
        + start
        + "</cac:AllowanceCharge>".len();
    let second = XML[start..end].replace(">15<", ">5<");
    assert_ne!(second, XML[start..end]);
    let xml = format!("{}{}{}", &XML[..end], second, &XML[end..]);
    invalid(&xml, "AllowanceCharge");
}

#[test]
fn malformed_xml_and_missing_lines_are_distinct_import_failures() {
    use fatoora_core::invoice::xml::parse::ParseError;
    for parse in [
        parse_finalized_invoice_xml("").map(|_| ()),
        parse_signed_invoice_xml("").map(|_| ()),
    ] {
        let error = parse.unwrap_err();
        assert!(matches!(error, ParseError::XmlParse(_)));
        assert_eq!(error.kind(), ErrorKind::Xml);
    }
    let doc = Parser::default().parse_string(XML).unwrap();
    let ctx = Context::new(&doc).unwrap();
    for mut node in ctx
        .evaluate("//*[local-name()='InvoiceLine']")
        .unwrap()
        .get_nodes_as_vec()
    {
        node.unlink();
    }
    assert!(matches!(
        parse_finalized_invoice_xml(&doc.to_string()),
        Err(ParseError::MissingField("VatCategory"))
    ));
    invalid(
        &change(
            XML,
            &format!("{ROOT}/cac:InvoiceLine[2]/cac:Item/cac:ClassifiedTaxCategory/cbc:ID"),
            "UNKNOWN",
        ),
        "LineVatCategory",
    );
}
