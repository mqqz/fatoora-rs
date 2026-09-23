use super::{
    FailureKind, Limits,
    ksa_fields::KsaFieldCheck as K,
    xml::{CAC, CBC, CREDIT_NOTE, UBL, XmlView},
};

fn view(namespace: &str, root: &str, body: &str) -> XmlView {
    XmlView::parse(
        &format!("<{root} xmlns='{namespace}' xmlns:cac='{CAC}' xmlns:cbc='{CBC}' xmlns:other='urn:other'>{body}</{root}>"),
        &Limits::default(),
    )
    .unwrap()
}

fn run(check: K, xml: &XmlView) -> Result<Vec<bool>, FailureKind> {
    check
        .contexts(xml)
        .into_iter()
        .map(|node| check.passes(xml, node))
        .collect()
}

fn check(check: K, body: &str) -> Result<Vec<bool>, FailureKind> {
    run(check, &view(UBL, "Invoice", body))
}

#[test]
fn invoice_type_preserves_executable_list_and_empty_substring_match() {
    for (value, expected) in [
        ("388", true),
        ("383", true),
        ("381", true),
        ("386", true),
        ("", true),
        (" \t\n", true),
        (" 388 ", true),
        ("380", false),
        ("38", false),
        ("0388", false),
        ("388 383", false),
        ("\u{a0}388", false),
        ("٣٨٨", false),
    ] {
        assert_eq!(
            check(
                K::InvoiceType,
                &format!("<cbc:InvoiceTypeCode>{value}</cbc:InvoiceTypeCode>")
            ),
            Ok(vec![expected]),
            "{value:?}"
        );
    }
    assert_eq!(
        check(
            K::InvoiceType,
            "<cbc:CreditNoteTypeCode>bad</cbc:CreditNoteTypeCode><other:InvoiceTypeCode>bad</other:InvoiceTypeCode>"
        ),
        Ok(vec![])
    );
    assert_eq!(
        run(
            K::InvoiceType,
            &view(
                CREDIT_NOTE,
                "CreditNote",
                "<cbc:InvoiceTypeCode>386</cbc:InvoiceTypeCode>"
            )
        ),
        Ok(vec![true])
    );
}

#[test]
fn transaction_code_checks_binary_flags_and_seven_to_nine_characters() {
    for (value, valid, length) in [
        ("0100000", true, true),
        ("0211111", true, true),
        ("01010101", true, true),
        ("021010101", true, true),
        ("", false, false),
        ("010000", false, false),
        ("0100000000", false, false),
        ("0300000", false, true),
        ("0100200", false, true),
        ("0100002", false, true),
        (" 0100000", false, true),
        ("0100000 ", false, true),
        ("01٠٠٠٠٠", false, true),
        ("💰💰💰💰💰💰💰", false, true),
    ] {
        let body = format!("<cbc:InvoiceTypeCode name='{value}'>388</cbc:InvoiceTypeCode>");
        assert_eq!(check(K::TransactionCode, &body), Ok(vec![valid]), "{value}");
        assert_eq!(
            check(K::TransactionLength, &body),
            Ok(vec![length]),
            "{value}"
        );
    }
    for body in [
        "<cbc:InvoiceTypeCode/>",
        "<cbc:InvoiceTypeCode other:name='0100000'/>",
    ] {
        assert_eq!(check(K::TransactionCode, body), Ok(vec![false]));
        assert_eq!(check(K::TransactionLength, body), Ok(vec![false]));
    }
}

#[test]
fn profile_requires_root_invoice_singleton_with_exact_normalized_text() {
    for (body, expected) in [
        ("<cbc:ProfileID>reporting:1.0</cbc:ProfileID>", true),
        ("<cbc:ProfileID> \treporting:1.0\n</cbc:ProfileID>", true),
        (
            "<cbc:ProfileID>reporting:<other:part>1.0</other:part></cbc:ProfileID>",
            true,
        ),
        ("", false),
        ("<cbc:ProfileID/>", false),
        ("<cbc:ProfileID>Reporting:1.0</cbc:ProfileID>", false),
        ("<cbc:ProfileID>\u{a0}reporting:1.0</cbc:ProfileID>", false),
        ("<other:ProfileID>reporting:1.0</other:ProfileID>", false),
        (
            "<cac:Wrapper><cbc:ProfileID>reporting:1.0</cbc:ProfileID></cac:Wrapper>",
            false,
        ),
    ] {
        assert_eq!(check(K::Profile, body), Ok(vec![expected]), "{body}");
    }
    assert_eq!(
        check(
            K::Profile,
            "<cbc:ProfileID>reporting:1.0</cbc:ProfileID><cbc:ProfileID/>"
        ),
        Err(FailureKind::Cardinality)
    );
    for (namespace, root) in [
        (CREDIT_NOTE, "CreditNote"),
        ("urn:other", "Invoice"),
        (UBL, "Other"),
    ] {
        assert_eq!(run(K::Profile, &view(namespace, root, "")), Ok(vec![]));
    }
    assert_eq!(
        run(
            K::Profile,
            &view("urn:other", "Wrapper", &format!("<Invoice xmlns='{UBL}'/>"))
        ),
        Ok(vec![])
    );
}

#[test]
fn tax_subtotal_total_counts_direct_totals_with_any_direct_subtotal() {
    for (body, expected) in [
        ("", false),
        ("<cac:TaxTotal/>", false),
        ("<cac:TaxTotal><cac:TaxSubtotal/></cac:TaxTotal>", true),
        (
            "<cac:TaxTotal/><cac:TaxTotal><cac:TaxSubtotal/><cac:TaxSubtotal/></cac:TaxTotal>",
            true,
        ),
        (
            "<cac:TaxTotal><cac:TaxSubtotal/></cac:TaxTotal><cac:TaxTotal><cac:TaxSubtotal/></cac:TaxTotal>",
            false,
        ),
        ("<cac:TaxTotal><other:TaxSubtotal/></cac:TaxTotal>", false),
        (
            "<cac:TaxTotal><cac:Wrapper><cac:TaxSubtotal/></cac:Wrapper></cac:TaxTotal>",
            false,
        ),
        (
            "<cac:InvoiceLine><cac:TaxTotal><cac:TaxSubtotal/></cac:TaxTotal></cac:InvoiceLine>",
            false,
        ),
    ] {
        assert_eq!(
            check(K::TaxSubtotalTotal, body),
            Ok(vec![expected]),
            "{body}"
        );
    }
    assert_eq!(
        run(K::TaxSubtotalTotal, &view(CREDIT_NOTE, "CreditNote", "")),
        Ok(vec![])
    );
}

#[test]
fn allowance_base_and_percentage_require_presence_without_casting_content() {
    for (body, base, percentage) in [
        ("<cbc:BaseAmount/>", vec![false], vec![]),
        ("<cbc:MultiplierFactorNumeric/>", vec![], vec![false]),
        (
            "<cbc:BaseAmount/><cbc:MultiplierFactorNumeric/>",
            vec![true],
            vec![true],
        ),
        (
            "<cbc:BaseAmount>bad</cbc:BaseAmount><cbc:MultiplierFactorNumeric>also bad</cbc:MultiplierFactorNumeric>",
            vec![true],
            vec![true],
        ),
        (
            "<cbc:BaseAmount/><cbc:BaseAmount/><cbc:MultiplierFactorNumeric/><cbc:MultiplierFactorNumeric/>",
            vec![true, true],
            vec![true, true],
        ),
        (
            "<cbc:BaseAmount/><other:MultiplierFactorNumeric/>",
            vec![false],
            vec![],
        ),
        (
            "<other:BaseAmount/><cbc:MultiplierFactorNumeric/>",
            vec![],
            vec![false],
        ),
    ] {
        let input = format!("<cac:AllowanceCharge>{body}</cac:AllowanceCharge>");
        assert_eq!(check(K::BasePercentage, &input), Ok(base));
        assert_eq!(check(K::PercentageBase, &input), Ok(percentage));
    }
    let body = "<cac:AllowanceCharge><cbc:BaseAmount/><cbc:MultiplierFactorNumeric/></cac:AllowanceCharge>";
    assert_eq!(
        run(K::BasePercentage, &view(CREDIT_NOTE, "CreditNote", body)),
        Ok(vec![])
    );
    assert_eq!(
        run(K::PercentageBase, &view(CREDIT_NOTE, "CreditNote", body)),
        Ok(vec![true])
    );
    assert_eq!(
        run(
            K::BasePercentage,
            &view(
                CREDIT_NOTE,
                "CreditNote",
                &format!("<cac:InvoiceLine>{body}</cac:InvoiceLine>")
            )
        ),
        Ok(vec![true])
    );
    assert_eq!(
        check(
            K::BasePercentage,
            &format!("<cac:CreditNoteLine>{body}</cac:CreditNoteLine>")
        ),
        Ok(vec![])
    );
    assert_eq!(
        check(
            K::BasePercentage,
            &format!("<cac:InvoiceLine><cac:Price>{body}</cac:Price></cac:InvoiceLine>")
        ),
        Ok(vec![])
    );
    assert_eq!(
        run(
            K::BasePercentage,
            &view(
                "urn:other",
                "Wrapper",
                &format!("<Invoice xmlns='{UBL}'>{body}</Invoice>")
            )
        ),
        Ok(vec![true])
    );
}

#[test]
fn price_charge_uses_boolean_comparison_and_exact_invoice_line_path() {
    for (indicator, expected) in [
        ("", Ok(vec![true])),
        (
            "<cbc:ChargeIndicator>false</cbc:ChargeIndicator>",
            Ok(vec![true]),
        ),
        (
            "<cbc:ChargeIndicator>0</cbc:ChargeIndicator>",
            Ok(vec![true]),
        ),
        (
            "<cbc:ChargeIndicator> true </cbc:ChargeIndicator>",
            Ok(vec![false]),
        ),
        (
            "<cbc:ChargeIndicator>1</cbc:ChargeIndicator>",
            Ok(vec![false]),
        ),
        (
            "<cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:ChargeIndicator>true</cbc:ChargeIndicator>",
            Ok(vec![false]),
        ),
        ("<cbc:ChargeIndicator/>", Err(FailureKind::InvalidBoolean)),
        (
            "<cbc:ChargeIndicator>bad</cbc:ChargeIndicator>",
            Err(FailureKind::InvalidBoolean),
        ),
        (
            "<cbc:ChargeIndicator>\u{a0}true</cbc:ChargeIndicator>",
            Err(FailureKind::InvalidBoolean),
        ),
    ] {
        let body = format!(
            "<cac:InvoiceLine><cac:Price><cac:AllowanceCharge>{indicator}</cac:AllowanceCharge></cac:Price></cac:InvoiceLine>"
        );
        assert_eq!(check(K::NoPriceCharge, &body), expected, "{indicator}");
    }
    let charge = "<cac:Price><cac:AllowanceCharge><cbc:ChargeIndicator>true</cbc:ChargeIndicator></cac:AllowanceCharge></cac:Price>";
    assert_eq!(
        check(
            K::NoPriceCharge,
            &format!("<cac:CreditNoteLine>{charge}</cac:CreditNoteLine>")
        ),
        Ok(vec![])
    );
    assert_eq!(
        run(
            K::NoPriceCharge,
            &view(
                CREDIT_NOTE,
                "CreditNote",
                &format!("<cac:InvoiceLine>{charge}</cac:InvoiceLine>")
            )
        ),
        Ok(vec![false])
    );
}

#[test]
fn base_unit_length_counts_unicode_scalars_and_keeps_attribute_cardinality() {
    for (unit, expected) in [
        ("", true),
        ("PCE", true),
        (&"💰".repeat(127), true),
        (&"💰".repeat(128), false),
    ] {
        let body = format!(
            "<cac:InvoiceLine><cac:Price><cbc:BaseQuantity unitCode='{unit}'>bad</cbc:BaseQuantity></cac:Price></cac:InvoiceLine>"
        );
        assert_eq!(check(K::BaseUnitLength, &body), Ok(vec![expected]));
    }
    assert_eq!(
        check(K::BaseUnitLength, "<cac:InvoiceLine/>"),
        Ok(vec![true])
    );
    assert_eq!(
        check(
            K::BaseUnitLength,
            "<cac:InvoiceLine><cac:Price><cbc:BaseQuantity/><cbc:BaseQuantity unitCode='PCE'/></cac:Price></cac:InvoiceLine>"
        ),
        Ok(vec![true])
    );
    assert_eq!(
        check(
            K::BaseUnitLength,
            "<cac:InvoiceLine><cac:Price><cbc:BaseQuantity unitCode=''/><cbc:BaseQuantity unitCode=''/></cac:Price></cac:InvoiceLine>"
        ),
        Err(FailureKind::Cardinality)
    );
    assert_eq!(
        check(
            K::BaseUnitLength,
            &format!(
                "<cac:InvoiceLine><cac:Price><cbc:BaseQuantity other:unitCode='{}'/></cac:Price></cac:InvoiceLine>",
                "x".repeat(128)
            )
        ),
        Ok(vec![true])
    );
}

#[test]
fn positive_base_quantity_uses_number_nan_and_raw_empty_guard() {
    for (value, expected) in [
        ("", true),
        ("1", true),
        (" .5 ", true),
        ("1E2", true),
        ("INF", true),
        ("1e5000", true),
        (" ", false),
        ("0", false),
        ("-0", false),
        ("-1", false),
        ("NaN", false),
        ("-INF", false),
        ("+INF", false),
        ("bad", false),
        ("\u{a0}1", false),
        ("1e-5000", false),
        ("١", false),
        ("1 2", false),
    ] {
        let body = format!(
            "<cac:InvoiceLine><cac:Price><cbc:BaseQuantity>{value}</cbc:BaseQuantity></cac:Price></cac:InvoiceLine>"
        );
        assert_eq!(
            check(K::PositiveBaseQuantity, &body),
            Ok(vec![expected]),
            "{value:?}"
        );
    }
    assert_eq!(
        check(
            K::PositiveBaseQuantity,
            "<cac:InvoiceLine><cac:Price/></cac:InvoiceLine><cbc:BaseQuantity>0</cbc:BaseQuantity><cac:CreditNoteLine><cac:Price><cbc:BaseQuantity>0</cbc:BaseQuantity></cac:Price></cac:CreditNoteLine>"
        ),
        Ok(vec![])
    );
    assert_eq!(
        run(
            K::PositiveBaseQuantity,
            &view(
                CREDIT_NOTE,
                "CreditNote",
                "<cac:InvoiceLine><cac:Price><cbc:BaseQuantity>2</cbc:BaseQuantity><cbc:BaseQuantity>bad</cbc:BaseQuantity></cac:Price></cac:InvoiceLine>"
            )
        ),
        Ok(vec![true, false])
    );
}
