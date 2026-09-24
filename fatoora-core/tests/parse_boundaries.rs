//! Mutate one field of an accepted fixture so rejection cannot be caused by an
//! unrelated missing field. Parsing checks supplied amounts; it is not validation.
use fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml;
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
