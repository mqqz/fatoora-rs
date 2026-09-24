//! Independent expected values from ZATCA XML standard section 10.
mod common;
use fatoora_core::invoice::{InvoiceBuilder, InvoiceSubType, InvoiceType, LineItem, VatCategory};

fn invoice(
    lines: Vec<LineItem>,
    discount: fatoora_core::Decimal,
    charge: fatoora_core::Decimal,
) -> fatoora_core::invoice::FinalizedInvoice {
    let mut b = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified));
    b = b
        .id("rounding")
        .uuid("rounding-uuid")
        .issue_datetime("2024-01-01T12:30:00Z")
        .currency("SAR")
        .previous_invoice_hash("hash")
        .invoice_counter(1)
        .seller(common::dummy_finalized_invoice().data().seller().clone())
        .payment_means_code("10")
        .vat_category(VatCategory::Standard)
        .invoice_level_discount(discount)
        .invoice_level_charge(charge);
    for line in lines {
        b = b.line_item(line);
    }
    b.build().unwrap()
}
fn line(
    price: fatoora_core::Decimal,
    quantity: fatoora_core::Decimal,
    rate: fatoora_core::Decimal,
) -> LineItem {
    LineItem::new("item", quantity, "PCE", price, rate, VatCategory::Standard).unwrap()
}
#[test]
fn zatca_two_decimal_examples_and_exact_midpoints() {
    for (input, expected) in [
        (d("123.4949"), d("123.49")),
        (d("123.4951"), d("123.50")),
        (d("1.005"), d("1.01")),
        (d("1.025"), d("1.03")),
        (d("1.0049"), d("1.00")),
    ] {
        assert_eq!(line(input, d("1.0"), d("0.0")).total_amount(), expected);
    }
}
#[test]
fn unit_price_is_not_rounded_before_multiplication() {
    assert_eq!(
        line(d("0.3333"), d("3.0"), d("0.0")).total_amount(),
        d("1.00")
    );
}
#[test]
fn document_vat_is_not_sum_of_rounded_line_vat() {
    let l = line(d("0.03"), d("1.0"), d("15.0"));
    assert_eq!(l.vat_amount(), d("0.00"));
    let inv = invoice(vec![l.clone(), l.clone(), l], d("0.0"), d("0.0"));
    assert_eq!(inv.totals().tax_amount(), d("0.01"));
    assert_eq!(inv.totals().tax_inclusive_amount(), d("0.10"));
}
#[test]
fn adjustments_change_document_vat_base() {
    let inv = invoice(
        vec![line(d("100.0"), d("1.0"), d("15.0"))],
        d("10.0"),
        d("2.0"),
    );
    assert_eq!(inv.totals().taxable_amount(), d("92.0"));
    assert_eq!(inv.totals().tax_amount(), d("13.80"));
    assert_eq!(inv.totals().tax_inclusive_amount(), d("105.80"));
}
#[test]
fn document_vat_groups_are_rounded_independently() {
    let inv = invoice(
        vec![
            line(d("0.03"), d("1.0"), d("15.0")),
            line(d("0.03"), d("1.0"), d("5.0")),
        ],
        d("0.0"),
        d("0.0"),
    );
    assert_eq!(inv.totals().tax_amount(), d("0.00"));
}
#[test]
fn one_cent_supplied_mismatch_is_rejected() {
    assert!(
        LineItem::try_from_parts(
            "item",
            d("1.0"),
            "PCE",
            d("1.0"),
            d("1.01"),
            d("0.0"),
            d("0.0"),
            VatCategory::Standard
        )
        .is_err()
    );
}
#[test]
fn subcent_supplied_amount_is_rejected() {
    assert!(
        LineItem::try_from_parts(
            "item",
            d("1.0"),
            "PCE",
            d("1.0"),
            d("1.001"),
            d("0.0"),
            d("0.0"),
            VatCategory::Standard
        )
        .is_err()
    );
}

fn d(s: &str) -> fatoora_core::Decimal {
    s.parse().unwrap()
}
#[test]
fn xml_preserves_price_precision_and_finalized_totals() {
    use fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml;
    let inv = invoice(vec![line(d("0.3333333"), d("3"), d("15"))], d("0"), d("0"));
    let xml = inv.to_xml().unwrap();
    assert!(xml.contains(">0.3333333</cbc:PriceAmount>"));
    assert!(xml.contains(">1.00</cbc:LineExtensionAmount>"));
    assert!(xml.contains(">0.15</cbc:TaxAmount>"));
    assert!(xml.contains(">1.15</cbc:TaxInclusiveAmount>"));
    let parsed = parse_finalized_invoice_xml(&xml).unwrap();
    assert_eq!(parsed.totals(), inv.totals());
    assert_eq!(parsed.data().line_items()[0].unit_price(), d("0.3333333"));
}
#[test]
fn xml_contains_each_vat_group() {
    let inv = invoice(
        vec![
            line(d("0.03"), d("1"), d("15")),
            line(d("0.03"), d("1"), d("5")),
        ],
        d("0"),
        d("0"),
    );
    assert_eq!(inv.totals().vat_breakdown().len(), 2);
    let xml = inv.to_xml().unwrap();
    assert_eq!(xml.matches("<cac:TaxSubtotal>").count(), 2);
}
#[test]
fn supplied_mismatch_reports_both_values() {
    let err = LineItem::try_from_parts(
        "item",
        d("1"),
        "PCE",
        d("1"),
        d("1.01"),
        d("0"),
        d("0"),
        VatCategory::Standard,
    )
    .unwrap_err();
    let fatoora_core::invoice::InvoiceError::Validation(err) = err else {
        panic!("wrong error")
    };
    assert_eq!(err.issues()[0].supplied(), Some(d("1.01")));
    assert_eq!(err.issues()[0].expected(), Some(d("1")));
}
#[test]
fn arithmetic_overflow_is_an_error() {
    assert!(
        LineItem::new(
            "item",
            d("79228162514264337593543950335"),
            "PCE",
            d("79228162514264337593543950335"),
            d("15"),
            VatCategory::Standard
        )
        .is_err()
    );
}
#[test]
fn parse_rejects_document_total_mismatch() {
    use fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml;
    let inv = invoice(vec![line(d("1"), d("1"), d("15"))], d("0"), d("0"));
    let xml = inv.to_xml().unwrap().replace(
        ">1.15</cbc:TaxInclusiveAmount>",
        ">1.16</cbc:TaxInclusiveAmount>",
    );
    assert!(parse_finalized_invoice_xml(&xml).is_err());
}
#[test]
fn line_vat_is_rounded_after_its_complete_calculation() {
    let item = line(d("0.034"), d("1"), d("15"));
    assert_eq!(item.total_amount(), d("0.03"));
    assert_eq!(item.vat_amount(), d("0.01"));
}
#[test]
fn official_payable_rounding_sample_preserves_supplied_line_vat() {
    use fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml;
    let xml = include_str!(
        "fixtures/invoices/Standard/Invoice/Standard Invoice with Payable Rounding Adjustment.xml"
    );
    let inv = parse_finalized_invoice_xml(xml).unwrap();
    assert_eq!(inv.data().line_items()[0].vat_amount(), d("130.43"));
    assert_eq!(inv.totals().tax_amount(), d("130.44"));
    assert_eq!(inv.totals().payable_rounding_amount(), d("-0.01"));
    assert_eq!(inv.totals().payable_amount(), d("1000"));
    assert!(
        inv.to_xml()
            .unwrap()
            .contains(">-0.01</cbc:PayableRoundingAmount>")
    );
}

/// Run against the official SDK's actual Schematron, without signing or network calls.
/// Set ZATCA_SDK_ROOT to the extracted SDK directory to enable this independent check.
#[test]
fn official_sdk_numeric_rules() {
    use std::process::Command;
    let Some(root) = std::env::var_os("ZATCA_SDK_ROOT") else {
        eprintln!("ZATCA_SDK_ROOT unset; SDK numeric check skipped");
        return;
    };
    let root = std::path::PathBuf::from(root);
    let jar = std::fs::read_dir(root.join("Apps"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "jar"))
        .unwrap();
    let dir = std::env::temp_dir().join(format!("fatoora-numeric-sdk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let invoices = [
        invoice(vec![line(d("0.03"), d("1"), d("15")); 3], d("0"), d("0")),
        invoice(vec![line(d("100"), d("1"), d("15"))], d("10"), d("2")),
        invoice(
            vec![
                line(d("0.034"), d("1"), d("15")),
                line(d("0.3333333"), d("3"), d("5")),
            ],
            d("0"),
            d("0"),
        ),
        invoice(vec![line(d("1"), d("1"), d("15"))], d("0"), d("0")),
    ];
    for (index, inv) in invoices.iter().enumerate() {
        let xml = inv.to_xml().unwrap();
        let xml = if index == 3 {
            xml.replace(
                ">1.15</cbc:TaxInclusiveAmount>",
                ">2.15</cbc:TaxInclusiveAmount>",
            )
        } else {
            xml
        };
        let path = dir.join(format!("{index}.xml"));
        std::fs::write(&path, &xml).unwrap();
        for stylesheet in [
            "CEN-EN16931-UBL.xsl",
            "20210819_ZATCA_E-invoice_Validation_Rules.xsl",
        ] {
            let report = dir.join("report.xml");
            let output = Command::new("java")
                .arg("-cp")
                .arg(&jar)
                .arg("net.sf.saxon.Transform")
                .arg(format!("-s:{}", path.display()))
                .arg(format!(
                    "-xsl:{}",
                    root.join("Data/Rules/Schematrons")
                        .join(stylesheet)
                        .display()
                ))
                .arg(format!("-o:{}", report.display()))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report = std::fs::read_to_string(report).unwrap();
            if index == 3 {
                if stylesheet == "CEN-EN16931-UBL.xsl" {
                    assert!(
                        report.contains("id=\"BR-CO-15\""),
                        "SDK failed to detect mutated total"
                    );
                }
                continue;
            }
            for rule in [
                "BR-CO-10",
                "BR-CO-11",
                "BR-CO-12",
                "BR-CO-13",
                "BR-CO-14",
                "BR-CO-15",
                "BR-CO-16",
                "BR-CO-17",
                "BR-S-08",
                "BR-S-09",
                "BR-KSA-51",
                "BR-KSA-EN16931-11",
                "BR-DEC-",
                "BR-KSA-DEC-",
            ] {
                assert!(
                    !report.contains(&format!("id=\"{rule}")),
                    "invoice {index}, {stylesheet}: {rule}\n{report}"
                );
            }
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn imported_category_tax_mismatch_is_rejected() {
    use fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml;
    let inv = invoice(vec![line(d("1"), d("1"), d("15"))], d("0"), d("0"));
    let xml = inv.to_xml().unwrap();
    let start = xml.find("<cac:TaxSubtotal>").unwrap();
    let changed = format!(
        "{}{}",
        &xml[..start],
        xml[start..].replacen(">0.15</cbc:TaxAmount>", ">0.16</cbc:TaxAmount>", 1)
    );
    assert!(parse_finalized_invoice_xml(&changed).is_err());
}

#[test]
fn adjustments_require_one_unambiguous_vat_group() {
    use fatoora_core::invoice::{InvoiceError, InvoiceField, ValidationKind};
    // Both lines are standard VAT, but the document discount has no rate selector.
    let error = invoice_builder_for_adjustments()
        .line_item(line(d("100"), d("1"), d("15")))
        .line_item(line(d("100"), d("1"), d("5")))
        .invoice_level_discount(d("10"))
        .build()
        .unwrap_err();
    let InvoiceError::Validation(validation) = error else {
        panic!("expected ambiguous VAT group")
    };
    assert!(
        validation
            .issues()
            .iter()
            .any(|issue| issue.field() == InvoiceField::VatCategory
                && issue.kind() == ValidationKind::Mismatch)
    );
    // A category absent from the invoice must not fall back to its first group.
    let error = invoice_builder_for_adjustments()
        .vat_category(VatCategory::Zero)
        .line_item(line(d("100"), d("1"), d("15")))
        .invoice_level_charge(d("10"))
        .build()
        .unwrap_err();
    let InvoiceError::Validation(validation) = error else {
        panic!("expected missing VAT group")
    };
    assert_eq!(validation.issues()[0].field(), InvoiceField::VatCategory);
}

fn invoice_builder_for_adjustments() -> fatoora_core::invoice::InvoiceBuilder {
    use fatoora_core::invoice::{InvoiceBuilder, InvoiceSubType, InvoiceType};
    InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified))
        .id("INV-ADJUSTMENT")
        .uuid("adjustment-uuid")
        .issue_datetime("2024-01-01T12:30:00Z")
        .currency("SAR")
        .previous_invoice_hash("hash")
        .invoice_counter(1)
        .seller(common::dummy_finalized_invoice().data().seller().clone())
        .payment_means_code("10")
        .vat_category(VatCategory::Standard)
}

#[test]
fn discount_cannot_make_its_tax_group_negative() {
    let at_limit = invoice_builder_for_adjustments()
        .line_item(line(d("100"), d("1"), d("15")))
        .invoice_level_discount(d("100"))
        .build()
        .unwrap();
    assert_eq!(at_limit.totals().taxable_amount(), d("0"));
    assert_eq!(at_limit.totals().payable_amount(), d("0"));
    let error: fatoora_core::Error = invoice_builder_for_adjustments()
        .line_item(line(d("100"), d("1"), d("15")))
        .invoice_level_discount(d("100.01"))
        .build()
        .unwrap_err()
        .into();
    let details: serde_json::Value = serde_json::from_str(&error.details_json()).unwrap();
    assert_eq!(details["issues"][0]["field"], "invoice_level_discount");
    assert_eq!(details["issues"][0]["kind"], "out_of_range");
}

#[test]
fn supplied_line_total_is_checked_before_accepting_computed_vat() {
    let valid = LineItem::from_totals(
        "Item",
        d("3"),
        "PCE",
        d("0.3333"),
        d("1"),
        d("15"),
        VatCategory::Standard,
    )
    .unwrap();
    assert_eq!(valid.unit_price(), d("0.3333"));
    assert_eq!(valid.total_amount(), d("1"));
    assert_eq!(valid.vat_amount(), d("0.15"));
    let error: fatoora_core::Error = LineItem::from_totals(
        "Item",
        d("3"),
        "PCE",
        d("0.3333"),
        d("1.01"),
        d("15"),
        VatCategory::Standard,
    )
    .unwrap_err()
    .into();
    let details: serde_json::Value = serde_json::from_str(&error.details_json()).unwrap();
    assert_eq!(details["issues"][0]["field"], "line_item_total_amount");
    assert_eq!(details["issues"][0]["supplied"], "1.01");
    assert_eq!(details["issues"][0]["expected"], "1");
}
