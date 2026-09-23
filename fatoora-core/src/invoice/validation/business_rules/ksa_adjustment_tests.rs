use super::{
    FailureKind, Limits,
    ksa_adjustments::KsaAdjustmentCheck as K,
    xml::{CAC, CBC, CREDIT_NOTE, UBL, XmlView},
};

fn run_in(
    rule: K,
    root: &str,
    namespace: &str,
    body: &str,
    digits: usize,
) -> Result<Vec<bool>, FailureKind> {
    let xml = XmlView::parse(
        &format!("<{root} xmlns='{namespace}' xmlns:cac='{CAC}' xmlns:cbc='{CBC}'>{body}</{root}>"),
        &Limits::default(),
    )?;
    rule.contexts(&xml)
        .into_iter()
        .map(|id| rule.passes(&xml, id, digits))
        .collect()
}
fn run(rule: K, body: &str) -> Result<Vec<bool>, FailureKind> {
    run_in(rule, "Invoice", UBL, body, 4096)
}
fn adjustment(indicator: &str, fields: &str) -> String {
    format!(
        "<cac:AllowanceCharge><cbc:ChargeIndicator>{indicator}</cbc:ChargeIndicator>{fields}</cac:AllowanceCharge>"
    )
}
fn line(fields: &str) -> String {
    format!("<cac:InvoiceLine>{fields}</cac:InvoiceLine>")
}

#[test]
fn allowance_percentage_preserves_raw_empty_and_lexical_scale_checks() {
    for (value, valid) in [
        ("", true),
        ("0", true),
        ("100", true),
        ("15.25", true),
        ("-0.00", true),
        ("-0.01", false),
        ("100.01", false),
        ("15.250", false),
        (" 1.23 ", false),
    ] {
        assert_eq!(
            run(
                K::AllowancePercentage,
                &adjustment(
                    "false",
                    &format!("<cbc:MultiplierFactorNumeric>{value}</cbc:MultiplierFactorNumeric>")
                )
            ),
            Ok(vec![valid]),
            "{value:?}"
        );
    }
    for value in [" ", "1e1", "NaN", "%"] {
        assert_eq!(
            run(
                K::AllowancePercentage,
                &adjustment(
                    "false",
                    &format!("<cbc:MultiplierFactorNumeric>{value}</cbc:MultiplierFactorNumeric>")
                )
            ),
            Err(FailureKind::InvalidDecimal)
        );
    }
    assert_eq!(
        run(K::AllowancePercentage, &adjustment("false", "")),
        Ok(vec![true])
    );
    assert_eq!(
        run(
            K::AllowancePercentage,
            &adjustment(
                "true",
                "<cbc:MultiplierFactorNumeric>bad</cbc:MultiplierFactorNumeric>"
            )
        ),
        Ok(vec![true])
    );
    assert_eq!(
        run(
            K::AllowancePercentage,
            &format!(
                "<cac:Price>{}</cac:Price>",
                adjustment(
                    "false",
                    "<cbc:MultiplierFactorNumeric>bad</cbc:MultiplierFactorNumeric>"
                )
            )
        ),
        Ok(vec![true])
    );
    assert_eq!(
        run(
            K::AllowancePercentage,
            &adjustment(
                "false",
                "<cbc:MultiplierFactorNumeric>1</cbc:MultiplierFactorNumeric><cbc:MultiplierFactorNumeric>2</cbc:MultiplierFactorNumeric>"
            )
        ),
        Err(FailureKind::Cardinality)
    );
    assert_eq!(
        run(K::AllowancePercentage, &adjustment("False", "")),
        Err(FailureKind::InvalidBoolean)
    );
}
#[test]
fn charge_reason_presence_is_normalized_scalar_and_keeps_document_line_scope() {
    for (rule, field, in_line) in [
        (
            K::DocumentChargeReasonCode,
            "AllowanceChargeReasonCode",
            false,
        ),
        (K::DocumentChargeReason, "AllowanceChargeReason", false),
        (K::LineChargeReasonCode, "AllowanceChargeReasonCode", true),
        (K::LineChargeReason, "AllowanceChargeReason", true),
    ] {
        let wrap = |fields: &str, charge: &str| {
            let a = adjustment(charge, fields);
            if in_line { line(&a) } else { a }
        };
        assert_eq!(run(rule, &wrap("", "true")), Ok(vec![false]));
        for (value, valid) in [
            ("", false),
            (" \t ", false),
            ("value", true),
            (" value ", true),
        ] {
            assert_eq!(
                run(
                    rule,
                    &wrap(&format!("<cbc:{field}>{value}</cbc:{field}>"), "true")
                ),
                Ok(vec![valid])
            );
        }
        assert_eq!(run(rule, &wrap("", "false")), Ok(vec![true]));
        assert_eq!(
            run(rule, &wrap("", "False")),
            Err(FailureKind::InvalidBoolean)
        );
        assert_eq!(
            run(
                rule,
                &wrap(
                    &format!("<cbc:{field}>a</cbc:{field}><cbc:{field}>b</cbc:{field}>"),
                    "true"
                )
            ),
            Err(FailureKind::Cardinality)
        );
        let wrong = if in_line {
            adjustment("true", "")
        } else {
            line(&adjustment("true", ""))
        };
        assert!(run(rule, &wrong).unwrap().is_empty());
    }
}
#[test]
fn optional_reason_lengths_keep_charge_allowance_and_unicode_boundaries() {
    for (rule, charge, in_line) in [
        (K::DocumentChargeReasonLength, "true", false),
        (K::LineChargeReasonLength, "true", true),
        (K::DocumentAllowanceReasonLength, "false", false),
        (K::LineAllowanceReasonLength, "false", true),
    ] {
        let wrap = |fields: &str, indicator: &str| {
            let a = adjustment(indicator, fields);
            if in_line { line(&a) } else { a }
        };
        assert_eq!(run(rule, &wrap("", charge)), Ok(vec![true]));
        for (length, valid) in [(0, false), (1, true), (1000, true), (1001, false)] {
            assert_eq!(
                run(
                    rule,
                    &wrap(
                        &format!(
                            "<cbc:AllowanceChargeReason>{}</cbc:AllowanceChargeReason>",
                            "ع".repeat(length)
                        ),
                        charge
                    )
                ),
                Ok(vec![valid])
            );
        }
        assert_eq!(
            run(
                rule,
                &wrap(
                    "<cbc:AllowanceChargeReason/><cbc:AllowanceChargeReason/>",
                    charge
                )
            ),
            Err(FailureKind::Cardinality)
        );
        assert_eq!(
            run(
                rule,
                &wrap(
                    "<cbc:AllowanceChargeReason/>",
                    if charge == "true" { "false" } else { "true" }
                )
            ),
            Ok(vec![true])
        );
    }
}
#[test]
fn outside_rates_use_general_double_comparisons_without_a_vat_scheme_gate() {
    for (rule, charge) in [
        (K::LineOutsideRate, None),
        (K::DocumentAllowanceOutsideRate, Some("false")),
        (K::DocumentChargeOutsideRate, Some("true")),
    ] {
        let wrap = |percent: &str, id: &str| {
            let category = format!("<cbc:ID>{id}</cbc:ID>{percent}");
            if let Some(charge) = charge {
                adjustment(
                    charge,
                    &format!("<cac:TaxCategory>{category}</cac:TaxCategory>"),
                )
            } else {
                line(&format!(
                    "<cac:Item><cac:ClassifiedTaxCategory>{category}</cac:ClassifiedTaxCategory></cac:Item>"
                ))
            }
        };
        assert_eq!(run(rule, &wrap("", " O ")), Ok(vec![true]));
        for (value, valid) in [
            ("0", true),
            ("-0", true),
            ("0e9", true),
            ("NaN", true),
            ("1", false),
            ("-1", false),
            ("INF", false),
            ("-INF", false),
        ] {
            assert_eq!(
                run(
                    rule,
                    &wrap(&format!("<cbc:Percent>{value}</cbc:Percent>"), "O")
                ),
                Ok(vec![valid]),
                "{rule:?}/{value}"
            );
        }
        assert_eq!(
            run(
                rule,
                &wrap(
                    "<cbc:Percent>0</cbc:Percent><cbc:Percent>1</cbc:Percent>",
                    "O"
                )
            ),
            Ok(vec![false])
        );
        assert_eq!(
            run(rule, &wrap("<cbc:Percent>bad</cbc:Percent>", "S")),
            Ok(vec![true])
        );
        assert_eq!(
            run(rule, &wrap("<cbc:Percent/>", "O")),
            Err(FailureKind::InvalidDouble)
        );
        assert_eq!(
            run(rule, &wrap("<cbc:ID>O</cbc:ID>", "O")),
            Err(FailureKind::Cardinality)
        );
    }
}
#[test]
fn buyer_other_identifier_fallback_tests_existence_of_the_local_vat_node() {
    let party = |fields: &str| {
        format!(
            "<cac:AccountingCustomerParty><cac:Party>{fields}</cac:Party></cac:AccountingCustomerParty>"
        )
    };
    let standard = |fields: &str| format!("<x name='prefix01١٢٣٤٥suffix'/>{}", party(fields));
    assert_eq!(run(K::BuyerOtherId, &party("")), Ok(vec![true]));
    assert_eq!(run(K::BuyerOtherId, &standard("")), Ok(vec![false]));
    assert_eq!(
        run(
            K::BuyerOtherId,
            &standard("<cac:PartyTaxScheme><cbc:CompanyID/></cac:PartyTaxScheme>")
        ),
        Ok(vec![true])
    );
    for (value, valid) in [("", false), (" ", false), ("123", true)] {
        assert_eq!(
            run(
                K::BuyerOtherId,
                &standard(&format!(
                    "<cac:PartyIdentification><cbc:ID>{value}</cbc:ID></cac:PartyIdentification>"
                ))
            ),
            Ok(vec![valid])
        );
    }
    assert_eq!(
        run(
            K::BuyerOtherId,
            &standard(
                "<cac:PartyIdentification><cbc:ID>a</cbc:ID><cbc:ID>b</cbc:ID></cac:PartyIdentification>"
            )
        ),
        Err(FailureKind::Cardinality)
    );
    assert_eq!(
        run(
            K::BuyerOtherId,
            &format!(
                "<x name='0100000'/><cac:InvoiceLine>{}</cac:InvoiceLine>",
                party("<cac:PartyTaxScheme><cbc:CompanyID>1</cbc:CompanyID></cac:PartyTaxScheme>")
            )
        ),
        Ok(vec![false])
    );
}
#[test]
fn tax_percentage_normalized_empty_bypass_differs_from_allowance_percentage() {
    for (prefix, suffix) in [
        (
            "<cac:AllowanceCharge><cac:TaxCategory>",
            "</cac:TaxCategory></cac:AllowanceCharge>",
        ),
        (
            "<cac:TaxTotal><cac:TaxSubtotal><cac:TaxCategory>",
            "</cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal>",
        ),
        (
            "<cac:InvoiceLine><cac:Item><cac:ClassifiedTaxCategory>",
            "</cac:ClassifiedTaxCategory></cac:Item></cac:InvoiceLine>",
        ),
        (
            "<cac:InvoiceLine><cac:TaxTotal><cac:TaxSubtotal><cac:TaxCategory>",
            "</cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal></cac:InvoiceLine>",
        ),
    ] {
        for (value, valid) in [
            ("", true),
            (" \t ", true),
            ("0", true),
            ("100", true),
            ("15.25", true),
            ("15.250", false),
            ("-0.1", false),
            ("100.1", false),
        ] {
            assert_eq!(
                run(
                    K::TaxPercentage,
                    &format!("{prefix}<cbc:Percent>{value}</cbc:Percent>{suffix}")
                ),
                Ok(vec![valid])
            );
        }
    }
    assert_eq!(
        run(K::TaxPercentage, "<cbc:Percent>bad</cbc:Percent>").unwrap(),
        Vec::<bool>::new()
    );
    assert_eq!(
        run(
            K::TaxPercentage,
            "<cac:AllowanceCharge><cac:TaxCategory><cbc:Percent>%</cbc:Percent></cac:TaxCategory></cac:AllowanceCharge>"
        ),
        Err(FailureKind::InvalidDecimal)
    );
}
#[test]
fn line_tax_scale_checks_preserve_raw_lexical_and_singleton_operands() {
    for (rule, field) in [
        (K::LineTaxScale, "TaxAmount"),
        (K::LineInclusiveScale, "RoundingAmount"),
    ] {
        for (value, valid) in [
            ("", true),
            ("1", true),
            ("1.23", true),
            ("1.230", false),
            ("1.23 ", false),
        ] {
            assert_eq!(
                run(
                    rule,
                    &line(&format!(
                        "<cac:TaxTotal><cbc:{field}>{value}</cbc:{field}></cac:TaxTotal>"
                    ))
                ),
                Ok(vec![valid])
            );
        }
        assert_eq!(run(rule, &line("")), Ok(vec![true]));
        assert_eq!(
            run(
                rule,
                &line(&format!(
                    "<cac:TaxTotal><cbc:{field}>1</cbc:{field}><cbc:{field}>2</cbc:{field}></cac:TaxTotal>"
                ))
            ),
            Err(FailureKind::Cardinality)
        );
    }
}
#[test]
fn gross_net_reconciliation_is_exact_decimal_subtraction_with_missing_values_distinct() {
    let price = |net: &str, base: &str, discount: &str| {
        line(&format!(
            "<cac:Price><cbc:PriceAmount>{net}</cbc:PriceAmount><cac:AllowanceCharge><cbc:Amount>{discount}</cbc:Amount><cbc:BaseAmount>{base}</cbc:BaseAmount></cac:AllowanceCharge></cac:Price>"
        ))
    };
    for (net, base, discount, valid) in [
        ("0.2", "0.3", "0.1", true),
        ("0.21", "0.3", "0.1", false),
        ("-0.2", "0.1", "0.3", true),
        (
            "1.000000000000000000000000000000000000001",
            "2.000000000000000000000000000000000000001",
            "1",
            true,
        ),
    ] {
        assert_eq!(
            run(K::GrossNet, &price(net, base, discount)),
            Ok(vec![valid])
        );
    }
    assert_eq!(
        run(K::GrossNet, &price("1", "", "1")),
        Err(FailureKind::InvalidDecimal)
    );
    assert_eq!(
        run(
            K::GrossNet,
            &line(
                "<cac:Price><cac:AllowanceCharge><cbc:BaseAmount>2</cbc:BaseAmount><cbc:Amount>1</cbc:Amount></cac:AllowanceCharge></cac:Price>"
            )
        ),
        Ok(vec![false])
    );
    assert_eq!(
        run(
            K::GrossNet,
            &price("1", "2", "1").replace(
                "<cbc:Amount>1</cbc:Amount>",
                "<cbc:Amount>1</cbc:Amount><cbc:Amount>1</cbc:Amount>"
            )
        ),
        Err(FailureKind::Cardinality)
    );
    assert_eq!(
        run_in(K::GrossNet, "Invoice", UBL, &price("9999", "9999", "-1"), 4),
        Err(FailureKind::Limit("decimal digits"))
    );
}
#[test]
fn root_invoice_scopes_and_context_boolean_casts_are_not_inferred_from_names() {
    for rule in [
        K::AllowancePercentage,
        K::DocumentChargeReasonCode,
        K::DocumentChargeReason,
        K::DocumentChargeReasonLength,
        K::LineChargeReasonCode,
        K::LineChargeReason,
        K::LineChargeReasonLength,
        K::DocumentAllowanceReasonLength,
        K::LineOutsideRate,
        K::DocumentAllowanceOutsideRate,
        K::DocumentChargeOutsideRate,
        K::LineAllowanceReasonLength,
        K::BuyerOtherId,
    ] {
        assert!(
            run_in(
                rule,
                "CreditNote",
                CREDIT_NOTE,
                &(adjustment("False", "") + &line(&adjustment("False", ""))),
                4096
            )
            .unwrap()
            .is_empty()
        );
    }
    for rule in [
        K::DocumentAllowanceOutsideRate,
        K::DocumentChargeOutsideRate,
    ] {
        assert_eq!(
            run(
                rule,
                &adjustment(
                    "False",
                    "<cac:TaxCategory><cbc:ID>O</cbc:ID></cac:TaxCategory>"
                )
            ),
            Err(FailureKind::InvalidBoolean)
        );
    }
}
