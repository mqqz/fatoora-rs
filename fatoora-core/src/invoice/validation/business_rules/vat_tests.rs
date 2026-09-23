use super::{
    FailureKind, Limits,
    vat::VatCheck as V,
    xml::{CAC, CBC, CREDIT_NOTE, UBL, XmlView},
};

fn document(body: &str, credit: bool) -> XmlView {
    let (namespace, name) = if credit {
        (CREDIT_NOTE, "CreditNote")
    } else {
        (UBL, "Invoice")
    };
    XmlView::parse(&format!("<{name} xmlns='{namespace}' xmlns:cac='{CAC}' xmlns:cbc='{CBC}' xmlns:x='urn:other'>{body}</{name}>"), &Limits::default()).unwrap()
}

fn run(check: V, body: &str) -> Result<Vec<bool>, FailureKind> {
    run_document(check, &document(body, false), 4096)
}

fn run_document(check: V, xml: &XmlView, digits: usize) -> Result<Vec<bool>, FailureKind> {
    check
        .contexts(xml)
        .into_iter()
        .map(|node| check.passes(xml, node, digits))
        .collect()
}

fn category(name: &str, code: &str, rate: Option<&str>) -> String {
    let rate = rate.map_or(String::new(), |value| {
        format!("<cbc:Percent>{value}</cbc:Percent>")
    });
    format!(
        "<cac:{name}><cbc:ID>{code}</cbc:ID>{rate}<cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:{name}>"
    )
}

fn line(code: &str, amount: &str) -> String {
    format!(
        "<cac:InvoiceLine><cbc:LineExtensionAmount>{amount}</cbc:LineExtensionAmount><cac:Item>{}</cac:Item></cac:InvoiceLine>",
        category("ClassifiedTaxCategory", code, Some("0"))
    )
}

fn adjustment(code: &str, amount: &str, charge: &str, rate: Option<&str>) -> String {
    format!(
        "<cac:AllowanceCharge><cbc:ChargeIndicator>{charge}</cbc:ChargeIndicator><cbc:Amount>{amount}</cbc:Amount>{}</cac:AllowanceCharge>",
        category("TaxCategory", code, rate)
    )
}

fn subtotal(code: &str, taxable: &str, tax: &str) -> String {
    format!(
        "<cac:TaxSubtotal><cbc:TaxableAmount>{taxable}</cbc:TaxableAmount><cbc:TaxAmount>{tax}</cbc:TaxAmount>{}</cac:TaxSubtotal>",
        category("TaxCategory", code, Some("0"))
    )
}

fn tax_total(code: &str, taxable: &str, tax: &str) -> String {
    format!(
        "<cac:TaxTotal>{}</cac:TaxTotal>",
        subtotal(code, taxable, tax)
    )
}

#[test]
fn required_breakdowns_follow_global_vat_categories_and_direct_totals() {
    for (check, code) in [
        (V::ExemptBreakdown, "E"),
        (V::OutsideBreakdown, "O"),
        (V::StandardBreakdown, "S"),
        (V::ZeroBreakdown, "Z"),
    ] {
        assert_eq!(run(check, ""), Ok(vec![true]));
        let item = line(code, "10");
        assert_eq!(run(check, &item), Ok(vec![false]));
        assert_eq!(
            run(check, &format!("{item}{}", tax_total(code, "10", "0"))),
            Ok(vec![true])
        );
        assert_eq!(
            run(
                check,
                &format!(
                    "{item}{}{}",
                    tax_total(code, "10", "0"),
                    tax_total(code, "10", "0")
                )
            ),
            Ok(vec![true])
        );
        assert_eq!(
            run(
                check,
                &format!(
                    "{item}<cac:InvoiceLine>{}</cac:InvoiceLine>",
                    tax_total(code, "10", "0")
                )
            ),
            Ok(vec![false])
        );
        assert_eq!(run(check, &item.replace(">VAT<", ">GST<")), Ok(vec![true]));
        let nested = format!(
            "<cac:Wrapper>{}</cac:Wrapper>",
            category("ClassifiedTaxCategory", code, None)
        );
        assert_eq!(run(check, &nested), Ok(vec![false]));
        let duplicate_id = item.replace(
            &format!("<cbc:ID>{code}</cbc:ID>"),
            &format!("<cbc:ID>other</cbc:ID><cbc:ID>{code}</cbc:ID>"),
        );
        assert_eq!(run(check, &duplicate_id), Ok(vec![false]));
        assert_eq!(
            run_document(check, &document(&item, true), 4096),
            Ok(vec![false])
        );
    }
}

#[test]
fn charge_zero_rate_uses_any_document_category_percent_without_association() {
    for (check, code) in [(V::ZeroChargeRate, "Z"), (V::ExemptChargeRate, "E")] {
        assert_eq!(run(check, ""), Ok(vec![true]));
        let charge = adjustment(code, "10", "true", Some("7"));
        assert_eq!(run(check, &charge), Ok(vec![false]));
        let unrelated_zero = adjustment("S", "1", "false", Some("0"));
        assert_eq!(
            run(check, &format!("{charge}{unrelated_zero}")),
            Ok(vec![true])
        );
        assert_eq!(
            run(check, &adjustment(code, "1", "false", Some("7"))),
            Ok(vec![true])
        );
        assert_eq!(
            run(check, &adjustment(code, "1", "true", None)),
            Ok(vec![false])
        );
        assert_eq!(
            run(check, &adjustment(code, "1", "true", Some("bad"))),
            Err(FailureKind::InvalidDouble)
        );
        assert_eq!(
            run(check, &adjustment(code, "1", "true", Some("0e10"))),
            Ok(vec![true])
        );
        assert_eq!(
            run_document(
                check,
                &document(&adjustment(code, "1", "true", Some("0")), true),
                4096
            ),
            Ok(vec![false])
        );
    }
}

fn rate_body(check: V, code: &str, rate: Option<&str>) -> String {
    match check {
        V::ExemptAllowanceRate | V::ZeroAllowanceRate | V::StandardAllowanceRate => {
            adjustment(code, "1", "false", rate)
        }
        V::StandardChargeRate => adjustment(code, "1", "true", rate),
        _ => format!(
            "<cac:InvoiceLine><cac:Item>{}</cac:Item></cac:InvoiceLine>",
            category("ClassifiedTaxCategory", code, rate)
        ),
    }
}

#[test]
fn exempt_and_zero_rates_cast_singleton_decimals() {
    for (check, code) in [
        (V::ExemptAllowanceRate, "E"),
        (V::ExemptItemRate, "E"),
        (V::ZeroAllowanceRate, "Z"),
        (V::ZeroItemRate, "Z"),
    ] {
        for (rate, expected) in [
            (Some("0"), Ok(vec![true])),
            (Some("-0.000"), Ok(vec![true])),
            (Some("1"), Ok(vec![false])),
            (None, Ok(vec![false])),
            (Some(""), Err(FailureKind::InvalidDecimal)),
            (Some("0e0"), Err(FailureKind::InvalidDecimal)),
        ] {
            assert_eq!(
                run(check, &rate_body(check, code, rate)),
                expected,
                "{check:?} {rate:?}"
            );
        }
        let repeated = rate_body(check, code, Some("0")).replace(
            "<cbc:Percent>0</cbc:Percent>",
            "<cbc:Percent>0</cbc:Percent><cbc:Percent>0</cbc:Percent>",
        );
        assert_eq!(run(check, &repeated), Err(FailureKind::Cardinality));
        let credit = rate_body(check, code, Some("0")).replace("InvoiceLine", "CreditNoteLine");
        assert_eq!(
            run_document(check, &document(&credit, true), 4096),
            Ok(vec![true])
        );
    }
}

#[test]
fn standard_rates_use_general_double_comparison_and_charge_template_priority() {
    for check in [
        V::StandardAllowanceRate,
        V::StandardChargeRate,
        V::StandardItemRate,
    ] {
        for (rate, expected) in [
            (Some("1e-2"), Ok(vec![true])),
            (Some("INF"), Ok(vec![true])),
            (Some("0"), Ok(vec![false])),
            (Some("-1"), Ok(vec![false])),
            (Some("NaN"), Ok(vec![false])),
            (None, Ok(vec![false])),
            (Some("bad"), Err(FailureKind::InvalidDouble)),
        ] {
            assert_eq!(
                run(check, &rate_body(check, "S", rate)),
                expected,
                "{check:?} {rate:?}"
            );
        }
        let repeated = rate_body(check, "S", Some("0")).replace(
            "<cbc:Percent>0</cbc:Percent>",
            "<cbc:Percent>0</cbc:Percent><cbc:Percent>15</cbc:Percent>",
        );
        assert_eq!(run(check, &repeated), Ok(vec![true]));
    }
    let both = adjustment("S", "1", "false", Some("0")).replace(
        "</cbc:ChargeIndicator>",
        "</cbc:ChargeIndicator><cbc:ChargeIndicator>true</cbc:ChargeIndicator>",
    );
    assert_eq!(run(V::StandardAllowanceRate, &both), Ok(vec![true]));
    assert_eq!(run(V::StandardChargeRate, &both), Ok(vec![false]));
    assert_eq!(
        run(
            V::StandardChargeRate,
            &adjustment("S", "1", "bad", Some("15"))
        ),
        Err(FailureKind::InvalidBoolean)
    );
    assert_eq!(
        run(
            V::StandardItemRate,
            &rate_body(V::StandardItemRate, "S", Some("0"))
                .replace("InvoiceLine", "CreditNoteLine")
        ),
        Ok(vec![])
    );
}

#[test]
fn category_contexts_preserve_scalar_identity_and_tax_scheme_association() {
    let body = rate_body(V::ExemptItemRate, "E", Some("0"));
    for (replacement, expected) in [
        ("<cbc:ID> E </cbc:ID>", Ok(vec![true])),
        ("<cbc:ID>\u{a0}E</cbc:ID>", Ok(vec![true])),
        (
            "<cbc:ID>E</cbc:ID><cbc:ID>E</cbc:ID>",
            Err(FailureKind::Cardinality),
        ),
    ] {
        assert_eq!(
            run(
                V::ExemptItemRate,
                &body.replacen("<cbc:ID>E</cbc:ID>", replacement, 1)
            ),
            expected
        );
    }
    let bad_rate = rate_body(V::ExemptItemRate, "E", Some("1"));
    assert_eq!(
        run(V::ExemptItemRate, &bad_rate.replace(">VAT<", "> vat <")),
        Ok(vec![false])
    );
    assert_eq!(
        run(V::ExemptItemRate, &bad_rate.replace(">VAT<", ">GST<")),
        Ok(vec![true])
    );
    assert_eq!(
        run(
            V::ExemptItemRate,
            &bad_rate.replace(
                "<cbc:ID>VAT</cbc:ID>",
                "<cbc:ID>VAT</cbc:ID><cbc:ID>VAT</cbc:ID>"
            )
        ),
        Err(FailureKind::Cardinality)
    );
    assert_eq!(
        run(
            V::ExemptItemRate,
            &bad_rate.replace("cac:ClassifiedTaxCategory", "x:ClassifiedTaxCategory")
        ),
        Ok(vec![])
    );
}

#[test]
fn exempt_outside_and_zero_taxable_amounts_sum_exact_document_values() {
    for (check, code) in [
        (V::ExemptTaxable, "E"),
        (V::OutsideTaxable, "O"),
        (V::ZeroTaxable, "Z"),
    ] {
        let transactions = format!(
            "{}{}{}",
            line(code, "100.125"),
            adjustment(code, "10.005", "false", Some("0")),
            adjustment(code, "20.08", "true", Some("0"))
        );
        assert_eq!(
            run(
                check,
                &format!("{transactions}{}", tax_total(code, "110.2", "0"))
            ),
            Ok(vec![true])
        );
        assert_eq!(
            run(
                check,
                &format!("{transactions}{}", tax_total(code, "110.20", "0"))
            ),
            Ok(vec![true])
        );
        assert_eq!(
            run(
                check,
                &format!("{transactions}{}", tax_total(code, "110.201", "0"))
            ),
            Ok(vec![false])
        );
        assert_eq!(run(check, &tax_total(code, "0", "0")), Ok(vec![false]));
        let transactions = format!(
            "{}{}",
            line(code, "100"),
            line(code, "20").replace(">VAT<", ">GST<")
        );
        assert_eq!(
            run(
                check,
                &format!("{transactions}{}", tax_total(code, "120", "0"))
            ),
            Ok(vec![true])
        );
        let credit = format!(
            "{}{}",
            line(code, "100").replace("InvoiceLine", "CreditNoteLine"),
            tax_total(code, "100", "0")
        );
        assert_eq!(
            run_document(check, &document(&credit, true), 4096),
            Ok(vec![false])
        );
    }
}

#[test]
fn taxable_sums_keep_empty_operands_cardinality_budgets_and_adjustment_overlap() {
    let empty_line =
        line("E", "").replace("<cbc:LineExtensionAmount></cbc:LineExtensionAmount>", "");
    assert_eq!(
        run(
            V::ExemptTaxable,
            &format!("{empty_line}{}", tax_total("E", "0", "0"))
        ),
        Ok(vec![true])
    );
    let repeated = line("E", "1").replace(
        "</cbc:LineExtensionAmount>",
        "</cbc:LineExtensionAmount><cbc:LineExtensionAmount>1</cbc:LineExtensionAmount>",
    );
    assert_eq!(
        run(
            V::ExemptTaxable,
            &format!("{repeated}{}", tax_total("E", "2", "0"))
        ),
        Err(FailureKind::Cardinality)
    );
    assert_eq!(
        run(
            V::ExemptTaxable,
            &format!("{}{}", line("E", "bad"), tax_total("E", "0", "0"))
        ),
        Err(FailureKind::InvalidDecimal)
    );
    let both = adjustment("E", "10", "false", Some("0")).replace(
        "</cbc:ChargeIndicator>",
        "</cbc:ChargeIndicator><cbc:ChargeIndicator>true</cbc:ChargeIndicator>",
    );
    assert_eq!(
        run(
            V::ExemptTaxable,
            &format!("{both}{}", tax_total("E", "0", "0"))
        ),
        Ok(vec![true])
    );
    let xml = document(
        &format!(
            "{}{}{}",
            line("E", "99"),
            line("E", "2"),
            tax_total("E", "0", "0")
        ),
        false,
    );
    assert_eq!(
        run_document(V::ExemptTaxable, &xml, 2),
        Err(FailureKind::Limit("decimal digits"))
    );
}

#[test]
fn standard_taxable_reconciliation_aggregates_subtotals_within_each_tax_total() {
    let lines = format!("{}{}", line("S", "100"), line("S", "50"));
    let total = format!(
        "<cac:TaxTotal>{}{}</cac:TaxTotal>",
        subtotal("S", "90", "0"),
        subtotal("S", "60", "0")
    );
    assert_eq!(
        run(V::StandardTaxable, &format!("{lines}{total}")),
        Ok(vec![true, true])
    );
    assert_eq!(
        run(
            V::StandardTaxable,
            &format!("{lines}{total}{}", tax_total("S", "1", "0"))
        ),
        Ok(vec![true, true, false])
    );
    let nonvat = subtotal("S", "60", "0").replace(">VAT<", ">GST<");
    assert_eq!(
        run(
            V::StandardTaxable,
            &format!(
                "{lines}<cac:TaxTotal>{}{nonvat}</cac:TaxTotal>",
                subtotal("S", "90", "0")
            )
        ),
        Ok(vec![true, true])
    );
    assert_eq!(
        run(V::StandardTaxable, &tax_total("S", "0", "0")),
        Ok(vec![false])
    );
}

#[test]
fn zero_tax_uses_parent_singleton_decimal_without_amount_rounding() {
    for (check, code) in [
        (V::ExemptTaxZero, "E"),
        (V::OutsideTaxZero, "O"),
        (V::ZeroTaxZero, "Z"),
    ] {
        for (value, expected) in [
            ("0", Ok(vec![true])),
            ("-0.000", Ok(vec![true])),
            ("0.001", Ok(vec![false])),
            ("", Err(FailureKind::InvalidDecimal)),
            ("NaN", Err(FailureKind::InvalidDecimal)),
        ] {
            assert_eq!(run(check, &tax_total(code, "1", value)), expected);
        }
        let missing = tax_total(code, "1", "0").replace("<cbc:TaxAmount>0</cbc:TaxAmount>", "");
        assert_eq!(run(check, &missing), Ok(vec![false]));
        let repeated = tax_total(code, "1", "0").replace(
            "</cbc:TaxAmount>",
            "</cbc:TaxAmount><cbc:TaxAmount>0</cbc:TaxAmount>",
        );
        assert_eq!(run(check, &repeated), Err(FailureKind::Cardinality));
    }
}

#[test]
fn standard_exemption_guard_compares_global_direct_text_without_trimming() {
    let reason = tax_total("S", "1", "0").replace(
        "</cac:TaxCategory>",
        "<cbc:TaxExemptionReason/></cac:TaxCategory>",
    );
    assert_eq!(run(V::StandardNoExemption, &reason), Ok(vec![false]));
    let spaced = reason.replace("<cbc:ID>S</cbc:ID>", "<cbc:ID> S </cbc:ID>");
    assert_eq!(run(V::StandardNoExemption, &spaced), Ok(vec![true]));
    let trigger = tax_total("x<!-- split -->S", "0", "0").replace(">VAT<", ">GST<");
    assert_eq!(
        run(V::StandardNoExemption, &format!("{spaced}{trigger}")),
        Ok(vec![false, true])
    );
    assert_eq!(
        run(V::StandardNoExemption, &tax_total("S", "1", "0")),
        Ok(vec![true])
    );
}

#[test]
fn sdk_float_rounding_boundaries_use_shortest_decimal_before_half_even() {
    // Unmodified SDK 238-R3.4.8 probes distinguish midpoint directions and
    // adjacent binary doubles using the one-line tolerance.
    for (taxable, tax, expected) in [
        ("1.005", "0.99", true),
        ("1.005", "1.02", false),
        ("2.675", "2.66", false),
        ("2.675", "2.69", true),
        ("1.015", "1.00", false),
        ("1.015", "1.03", true),
        ("-1.005", "-1.02", false),
        ("-1.005", "-0.99", true),
        ("-2.675", "-2.69", true),
        ("-2.675", "-2.66", false),
        ("2.6749999999999994", "2.66", true),
        ("2.6749999999999994", "2.69", false),
        ("2.6750000000000003", "2.66", false),
        ("2.6750000000000003", "2.69", true),
        ("2.67499999999999", "2.66", true),
        ("2.67499999999999", "2.69", false),
        ("2.67500000000001", "2.66", false),
        ("2.67500000000001", "2.69", true),
        ("1.0149999999999997", "1.00", true),
        ("1.0149999999999997", "1.03", false),
        ("1.0150000000000001", "1.00", false),
        ("1.0150000000000001", "1.03", true),
    ] {
        let body = format!("<cac:InvoiceLine/>{}", tax_total("S", taxable, tax)).replace(
            "<cbc:Percent>0</cbc:Percent>",
            "<cbc:Percent>100</cbc:Percent>",
        );
        for check in [V::TaxComputation, V::StandardTaxComputation] {
            assert_eq!(
                run(check, &body),
                Ok(vec![expected]),
                "{check:?}: {taxable}, {tax}"
            );
        }
    }
}

#[test]
fn float_tax_computation_preserves_tolerance_contexts_and_invalid_scalars() {
    let base = tax_total("S", "100", "15.01").replace(
        "<cbc:Percent>0</cbc:Percent>",
        "<cbc:Percent>15</cbc:Percent>",
    );
    assert_eq!(run(V::TaxComputation, &base), Ok(vec![false]));
    assert_eq!(
        run(V::TaxComputation, &format!("<cac:InvoiceLine/>{base}")),
        Ok(vec![true])
    );
    assert_eq!(
        run(
            V::TaxComputation,
            &format!("<cac:Wrapper><cac:InvoiceLine/></cac:Wrapper>{base}")
        ),
        Ok(vec![true])
    );
    assert_eq!(
        run(V::TaxComputation, &format!("<cac:CreditNoteLine/>{base}")),
        Ok(vec![false])
    );
    assert_eq!(
        run_document(V::TaxComputation, &document(&base, true), 4096),
        Ok(vec![])
    );
    assert_eq!(
        run_document(V::StandardTaxComputation, &document(&base, true), 4096),
        Ok(vec![false])
    );
    for field in ["TaxAmount", "TaxableAmount", "Percent"] {
        let start = format!("<cbc:{field}>");
        let end = format!("</cbc:{field}>");
        let from = base.find(&start).unwrap() + start.len();
        let to = base[from..].find(&end).unwrap() + from;
        let mut invalid = base.clone();
        invalid.replace_range(from..to, "bad");
        assert_eq!(
            run(V::TaxComputation, &invalid),
            Err(FailureKind::InvalidDouble),
            "{field}"
        );
        let duplicate = base.replace(&end, &format!("{end}<cbc:{field}>1</cbc:{field}>"));
        assert_eq!(
            run(V::TaxComputation, &duplicate),
            Err(FailureKind::Cardinality),
            "{field}"
        );
        let mut missing = base.clone();
        missing.replace_range(from - start.len()..to + end.len(), "");
        assert_eq!(run(V::TaxComputation, &missing), Ok(vec![false]), "{field}");
    }
    let empty_rate = base.replace("<cbc:Percent>15</cbc:Percent>", "<cbc:Percent/>");
    assert_eq!(run(V::StandardTaxComputation, &empty_rate), Ok(vec![false]));
    assert_eq!(
        run(V::TaxComputation, &empty_rate),
        Err(FailureKind::InvalidDouble)
    );
    let nonvat = base.replace(
        "</cac:TaxSubtotal>",
        &format!(
            "{}</cac:TaxSubtotal>",
            category("TaxCategory", "other", Some("bad")).replace(">VAT<", ">GST<")
        ),
    );
    assert_eq!(
        run(V::TaxComputation, &format!("<cac:InvoiceLine/>{nonvat}")),
        Ok(vec![true])
    );
}
