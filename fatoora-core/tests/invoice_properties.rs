//! Generated financial cases use integer cents as the independent oracle.
mod common;
use fatoora_core::Decimal;
use fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml;
use fatoora_core::invoice::{
    FinalizedInvoice, InvoiceBuilder, InvoiceFlags, InvoiceNote, InvoiceSubType, InvoiceType,
    LineItem, OriginalInvoiceRef, VatCategory,
};
use proptest::prelude::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
struct Line {
    // Quantity thousandths, price ten-thousandths. Keep products within i128.
    quantity: i128,
    price: i128,
    group: u8,
}
fn category(group: u8) -> VatCategory {
    match group {
        0 | 4 => VatCategory::Standard,
        1 => VatCategory::Zero,
        2 => VatCategory::Exempt,
        3 => VatCategory::OutOfScope,
        _ => unreachable!(),
    }
}
fn rate(group: u8) -> i128 {
    match group {
        0 => 15,
        4 => 5,
        _ => 0,
    }
}
fn decimal(value: i128, scale: u32) -> Decimal {
    let digits = format!("{:0width$}", value.abs(), width = scale as usize + 1);
    let at = digits.len() - scale as usize;
    let sign = if value < 0 { "-" } else { "" };
    format!("{sign}{}.{}", &digits[..at], &digits[at..])
        .parse()
        .unwrap()
}
fn net(line: &Line) -> i128 {
    (line.quantity * line.price + 50_000) / 100_000
}
fn lines() -> impl Strategy<Value = Vec<Line>> {
    prop::collection::vec(
        (
            1i128..=100_000,
            prop_oneof![Just(0), Just(50), Just(3333), 0i128..=1_000_000],
            0u8..5,
        )
            .prop_map(|(quantity, price, group)| Line {
                quantity,
                price,
                group,
            }),
        1..9,
    )
}
fn text() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec!["", " ", "\n", "\r\n", "\t"]),
        prop::collection::vec(
            prop::sample::select(vec![
                'a', 'ش', '中', '&', '<', '>', '\'', '"', ' ', '\n', '\r', '\t',
            ]),
            0..24,
        ),
        prop::sample::select(vec!["", " ", "\n", "\r\n", "\t"]),
    )
        .prop_map(|(prefix, chars, suffix)| {
            format!(
                "{prefix}X{}X{suffix}",
                chars.into_iter().collect::<String>()
            )
        })
}
fn groups(lines: &[Line]) -> BTreeMap<u8, i128> {
    let mut groups = BTreeMap::new();
    for line in lines {
        *groups.entry(line.group).or_default() += net(line);
    }
    groups
}
fn adjustments(lines: &[Line], percent: u8, charge: i128) -> (i128, i128) {
    let groups = groups(lines);
    // The public builder cannot select between two standard rates. Those cases
    // still exercise mixed-rate totals; adjustments use unambiguous groups.
    if category(lines[0].group) == VatCategory::Standard
        && groups.contains_key(&0)
        && groups.contains_key(&4)
    {
        return (0, 0);
    }
    (groups[&lines[0].group] * i128::from(percent) / 100, charge)
}
fn build(
    lines: &[Line],
    discount: i128,
    charge: i128,
    selected: u8,
    kind: InvoiceType,
    text: &str,
    flags: u8,
) -> FinalizedInvoice {
    let kind = match kind {
        InvoiceType::CreditNote(subtype, reference, _) => {
            InvoiceType::CreditNote(subtype, reference, text.to_owned())
        }
        InvoiceType::DebitNote(subtype, reference, _) => {
            InvoiceType::DebitNote(subtype, reference, text.to_owned())
        }
        other => other,
    };
    let template = common::dummy_finalized_invoice();
    let mut address = template.data().seller().address().clone();
    address.street = text.to_owned();
    address.city = text.to_owned();
    address.district = Some(text.to_owned());
    address.additional_street = Some(text.to_owned());
    let seller =
        fatoora_core::invoice::Seller::new(text.to_owned(), address, "399999999900003", None)
            .unwrap();
    let mut builder = InvoiceBuilder::new(kind)
        .id("PROPERTY-1")
        .uuid("property-uuid")
        .issue_datetime("2024-01-01T12:30:00Z")
        .currency("SAR")
        .previous_invoice_hash("hash")
        .invoice_counter(42)
        .seller(seller)
        .payment_means_code("10")
        .vat_category(category(selected))
        .flags(InvoiceFlags::from_bits(flags).unwrap())
        .note(InvoiceNote::new("ar", text))
        .invoice_level_discount(decimal(discount, 2))
        .invoice_level_charge(decimal(charge, 2))
        .allowance_reason(text);
    for line in lines {
        builder = builder.line_item(
            LineItem::new(
                text,
                decimal(line.quantity, 3),
                "PCE",
                decimal(line.price, 4),
                Decimal::from(rate(line.group) as i64),
                category(line.group),
            )
            .unwrap(),
        );
    }
    builder.build().unwrap()
}
fn kind(code: u8, standard: bool) -> InvoiceType {
    let subtype = if standard {
        InvoiceSubType::Standard
    } else {
        InvoiceSubType::Simplified
    };
    let reference = OriginalInvoiceRef::new("ORIGINAL")
        .with_uuid("original-uuid")
        .with_issue_date_str("2023-12-31")
        .unwrap();
    match code {
        0 => InvoiceType::Tax(subtype),
        1 => InvoiceType::Prepayment(subtype),
        2 => InvoiceType::CreditNote(subtype, reference, "Adjustment".into()),
        _ => InvoiceType::DebitNote(subtype, reference, "Adjustment".into()),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"))), ..ProptestConfig::default() })]
    #[test]
    fn property_invoice_totals_match_grouped_integer_oracle(lines in lines(), percent in 0u8..=100, charge in 0i128..=10_000) {
        let (discount, charge) = adjustments(&lines, percent, charge);
        let invoice = build(&lines, discount, charge, lines[0].group, kind(0, false), "Item", 0);
        let mut expected_groups = groups(&lines);
        *expected_groups.get_mut(&lines[0].group).unwrap() += charge - discount;
        let line_extension: i128 = lines.iter().map(net).sum();
        let tax: i128 = expected_groups.iter().map(|(group, base)| (base * rate(*group) + 50) / 100).sum();
        prop_assert_eq!(invoice.totals().line_extension(), decimal(line_extension, 2));
        prop_assert_eq!(invoice.totals().taxable_amount(), decimal(line_extension - discount + charge, 2));
        prop_assert_eq!(invoice.totals().tax_amount(), decimal(tax, 2));
        prop_assert_eq!(invoice.totals().payable_amount(), decimal(line_extension - discount + charge + tax, 2));
        prop_assert_eq!(invoice.totals().vat_breakdown().len(), expected_groups.len());
        for (group, base) in &expected_groups {
            let actual = invoice.totals().vat_breakdown().iter().find(|g| g.category() == category(*group) && g.rate() == Decimal::from(rate(*group) as i64)).unwrap();
            prop_assert_eq!(actual.taxable_amount(), decimal(*base, 2));
            prop_assert_eq!(actual.tax_amount(), decimal((base * rate(*group) + 50) / 100, 2));
        }
        for (source, actual) in lines.iter().zip(invoice.data().line_items()) {
            prop_assert_eq!(actual.total_amount(), decimal(net(source), 2));
            prop_assert_eq!(actual.vat_amount(), decimal((source.quantity * source.price * rate(source.group) + 5_000_000) / 10_000_000, 2));
        }
        let reversed: Vec<_> = lines.iter().rev().cloned().collect();
        let reordered = build(&reversed, discount, charge, lines[0].group, kind(0, false), "Item", 0);
        prop_assert_eq!(reordered.totals().payable_amount(), invoice.totals().payable_amount());
        prop_assert_eq!(reordered.totals().tax_amount(), invoice.totals().tax_amount());
    }

    #[test]
    fn property_xml_preserves_modeled_fields(lines in lines(), percent in 0u8..=100, charge in 0i128..=10_000, text in text(), flags in 0u8..32, code in 0u8..4, standard in any::<bool>()) {
        let (discount, charge) = adjustments(&lines, percent, charge);
        let invoice = build(&lines, discount, charge, lines[0].group, kind(code, standard), &text, flags);
        let xml = invoice.to_xml().unwrap();
        let parsed = parse_finalized_invoice_xml(&xml).unwrap();
        let (a, b) = (invoice.data(), parsed.data());
        // Explicit supported projection: buyer and arbitrary UBL extensions are
        // not imported. Signed XML byte identity has a separate contract.
        prop_assert_eq!(a.id(), b.id());
        prop_assert_eq!(a.uuid(), b.uuid());
        prop_assert_eq!(a.issue_datetime(), b.issue_datetime());
        prop_assert_eq!(a.currency(), b.currency());
        prop_assert_eq!(a.invoice_type(), b.invoice_type());
        prop_assert_eq!(a.flags(), b.flags());
        prop_assert_eq!(a.seller(), b.seller());
        prop_assert_eq!(a.note(), b.note());
        prop_assert_eq!(a.allowance_reason(), b.allowance_reason());
        prop_assert_eq!(a.line_items(), b.line_items());
        prop_assert_eq!(a.previous_invoice_hash(), b.previous_invoice_hash());
        prop_assert_eq!(a.invoice_counter(), b.invoice_counter());
        prop_assert_eq!(a.payment_means_code(), b.payment_means_code());
        prop_assert_eq!(a.invoice_level_discount(), b.invoice_level_discount());
        prop_assert_eq!(a.invoice_level_charge(), b.invoice_level_charge());
        prop_assert_eq!(invoice.totals(), parsed.totals());
    }
}

fn set_amount(doc: &libxml::tree::Document, field: &str, cents: i128) {
    let ctx = libxml::xpath::Context::new(doc).unwrap();
    let path = format!(
        "/*[local-name()='Invoice']/*[local-name()='LegalMonetaryTotal']/*[local-name()='{field}']"
    );
    let mut nodes = ctx.evaluate(&path).unwrap().get_nodes_as_vec();
    assert_eq!(nodes.len(), 1);
    nodes[0]
        .set_content(&decimal(cents, 2).to_string())
        .unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"))), ..ProptestConfig::default() })]
    #[test]
    fn property_imported_payable_equation_rejects_one_cent_tampering(price in 0i128..=1_000_000, paid_percent in 0i128..=100, rounding in -99i128..=99) {
        let lines = [Line { quantity: 1000, price, group: 0 }];
        let invoice = build(&lines, 0, 0, 0, kind(0, false), "Item", 0);
        let net = net(&lines[0]);
        let inclusive = net + (net * 15 + 50) / 100;
        let prepaid = inclusive * paid_percent / 100;
        let payable = inclusive - prepaid + rounding;
        let doc = libxml::parser::Parser::default().parse_string(invoice.to_xml().unwrap()).unwrap();
        for (field, cents) in [("PrepaidAmount", prepaid), ("PayableRoundingAmount", rounding), ("PayableAmount", payable)] {
            set_amount(&doc, field, cents);
        }
        let parsed = parse_finalized_invoice_xml(&doc.to_string()).unwrap();
        prop_assert_eq!(parsed.totals().prepaid_amount(), decimal(prepaid, 2));
        prop_assert_eq!(parsed.totals().payable_rounding_amount(), decimal(rounding, 2));
        prop_assert_eq!(parsed.totals().payable_amount(), decimal(payable, 2));
        let reparsed = parse_finalized_invoice_xml(&parsed.to_xml().unwrap()).unwrap();
        prop_assert_eq!(parsed.totals(), reparsed.totals());
        set_amount(&doc, "PayableAmount", payable + 1);
        let error = parse_finalized_invoice_xml(&doc.to_string()).unwrap_err();
        prop_assert!(matches!(error, fatoora_core::invoice::xml::parse::ParseError::InvalidValue { field: "PayableAmount", .. }), "unexpected error: {error}");
    }
}

#[test]
fn free_text_survives_xml_serialization_and_signing() {
    use fatoora_core::invoice::{
        sign::InvoiceSigner,
        xml::{XmlFormat, parse::parse_signed_invoice_xml},
    };
    let signer = InvoiceSigner::from_der(
        include_bytes!("fixtures/sdk-parity/credentials/certificate.der"),
        include_bytes!("fixtures/sdk-parity/credentials/private-key.der"),
    )
    .unwrap();
    for text in [
        "X\rX",
        "X\r\nX",
        "X\nX",
        "X&#13;X",
        "ش & <\r> 中",
        " \tX\r\nX\n ",
    ] {
        let invoice = build(
            &[Line {
                quantity: 1000,
                price: 10000,
                group: 0,
            }],
            0,
            0,
            0,
            kind(0, false),
            text,
            0,
        );
        for format in [
            XmlFormat::Compact,
            XmlFormat::Pretty {
                indent_char: ' ',
                indent_size: 2,
            },
        ] {
            let xml = invoice.to_xml_with_format(format).unwrap();
            let parsed = parse_finalized_invoice_xml(&xml).unwrap();
            assert_eq!(parsed.data().note().unwrap().text(), text);
            assert_eq!(parsed.data().line_items()[0].description(), text);
        }
        let signed = invoice.sign(&signer).unwrap();
        let parsed = parse_signed_invoice_xml(signed.xml()).unwrap();
        assert_eq!(parsed.data().note().unwrap().text(), text);
        assert_eq!(parsed.data().line_items()[0].description(), text);
        assert_eq!(parsed.hash_base64().unwrap(), signed.invoice_hash());
    }
}
