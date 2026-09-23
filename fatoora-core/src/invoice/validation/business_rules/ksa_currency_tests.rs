use super::{
    FailureKind, Limits,
    ksa_currency::KsaCurrencyCheck as K,
    xml::{CAC, CBC, UBL, XmlView},
};
fn view(body: &str) -> XmlView {
    XmlView::parse(
        &format!("<Invoice xmlns='{UBL}' xmlns:cac='{CAC}' xmlns:cbc='{CBC}'>{body}</Invoice>"),
        &Limits::default(),
    )
    .unwrap()
}
fn run(check: K, body: &str) -> Result<Vec<bool>, FailureKind> {
    let xml = view(body);
    let patterns = super::patterns::MatchCache::default();
    check
        .contexts(&xml)?
        .into_iter()
        .map(|n| check.passes(&xml, n, &patterns))
        .collect()
}
#[test]
fn currency_membership_keeps_attribute_presence_and_source_contexts() {
    for (value, pass) in [
        ("SAR", true),
        (" SAR ", true),
        ("sar", false),
        ("", false),
        ("XXX", true),
        ("MRO", true),
        ("MRU", false),
    ] {
        assert_eq!(
            run(
                K::CurrencyCode,
                &format!("<cbc:DocumentCurrencyCode>{value}</cbc:DocumentCurrencyCode>")
            ),
            Ok(vec![pass])
        );
        assert_eq!(
            run(
                K::CurrencyCode,
                &format!(
                    "<cac:LegalMonetaryTotal><cbc:PayableRoundingAmount currencyID='{value}'>0</cbc:PayableRoundingAmount></cac:LegalMonetaryTotal>"
                )
            ),
            Ok(vec![pass])
        );
    }
    assert_eq!(
        run(
            K::CurrencyCode,
            "<cac:LegalMonetaryTotal><cbc:PayableRoundingAmount>0</cbc:PayableRoundingAmount></cac:LegalMonetaryTotal><cbc:TaxCurrencyCode>BAD</cbc:TaxCurrencyCode>"
        ),
        Ok(vec![])
    );
    let xml = view(
        "<cac:InvoiceLine><cac:TaxTotal><cac:TaxSubtotal><cbc:TaxAmount currencyID='BAD'>0</cbc:TaxAmount></cac:TaxSubtotal></cac:TaxTotal></cac:InvoiceLine>",
    );
    let id = K::CurrencyCode.contexts(&xml).unwrap()[0];
    assert!(K::CurrencyCode.location(&xml, id).ends_with("/@currencyID"));
}
#[test]
fn currency_equality_uses_xpath_regex_and_global_singletons() {
    for (value, pass) in [
        ("SAR", true),
        ("S", true),
        ("S.R", true),
        ("[A-Z]+", true),
        ("USD", false),
        ("", false),
        (" SAR ", false),
    ] {
        assert_eq!(
            run(
                K::AmountCurrency,
                &format!(
                    "<cbc:DocumentCurrencyCode> SAR </cbc:DocumentCurrencyCode><cbc:Amount currencyID='{value}'>0</cbc:Amount>"
                )
            ),
            Ok(vec![pass])
        );
    }
    assert_eq!(
        run(K::AmountCurrency, "<cbc:Amount>0</cbc:Amount>"),
        Ok(vec![false])
    );
    assert_eq!(
        run(
            K::AmountCurrency,
            "<cbc:Amount currencyID='['>0</cbc:Amount>"
        ),
        Err(FailureKind::InvalidRegex)
    );
    assert_eq!(
        run(
            K::AmountCurrency,
            "<cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode><cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode><cbc:Amount currencyID='SAR'>0</cbc:Amount>"
        ),
        Err(FailureKind::Cardinality)
    );
    // A document TaxTotal's TaxAmount is exempt from this amount-currency rule.
    assert_eq!(
        run(
            K::AmountCurrency,
            "<cac:TaxTotal><cbc:TaxAmount currencyID='BAD'>1</cbc:TaxAmount></cac:TaxTotal>"
        ),
        Ok(vec![])
    );
}
#[test]
fn exchange_requirements_repeat_on_each_source_context() {
    let currencies = "<cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode><cbc:TaxCurrencyCode>SAR</cbc:TaxCurrencyCode>";
    for (body, pass) in [
        ("", true),
        ("<cac:TaxExchangeRate/>", false),
        (
            "<cac:TaxExchangeRate><cbc:SourceCurrencyCode> </cbc:SourceCurrencyCode><cbc:TargetCurrencyCode> </cbc:TargetCurrencyCode><cbc:CalculationRate> </cbc:CalculationRate></cac:TaxExchangeRate>",
            true,
        ),
    ] {
        assert_eq!(
            run(K::ExchangeFields, &format!("{currencies}{body}")),
            Ok(vec![pass; if body.is_empty() { 2 } else { 3 }])
        );
    }
    for (check, field) in [
        (K::ExchangeSource, "SourceCurrencyCode"),
        (K::ExchangeTarget, "TargetCurrencyCode"),
    ] {
        for (value, pass) in [("S", true), ("SAR", true), ("USD", false), ("", true)] {
            assert_eq!(
                run(
                    check,
                    &format!(
                        "{currencies}<cac:TaxExchangeRate><cbc:{field}>{value}</cbc:{field}></cac:TaxExchangeRate>"
                    )
                ),
                Ok(vec![pass; 3])
            );
        }
    }
    for (value, pass) in [
        ("12345678901234", true),
        ("123456789012345", false),
        (" 1.23 ", true),
        ("", true),
    ] {
        assert_eq!(
            run(
                K::ExchangeRateLength,
                &format!(
                    "{currencies}<cac:TaxExchangeRate><cbc:CalculationRate>{value}</cbc:CalculationRate></cac:TaxExchangeRate>"
                )
            ),
            Ok(vec![pass; 3])
        );
    }
}
#[test]
fn boolean_comparisons_cast_xml_booleans_and_reject_bad_lexical_values() {
    for value in ["true", "false", "1", "0", " true "] {
        assert_eq!(
            run(
                K::Boolean,
                &format!(
                    "<cac:AllowanceCharge><cbc:ChargeIndicator>{value}</cbc:ChargeIndicator></cac:AllowanceCharge>"
                )
            ),
            Ok(vec![true])
        );
    }
    for value in ["True", "", "yes"] {
        assert_eq!(
            run(
                K::Boolean,
                &format!(
                    "<cac:AllowanceCharge><cbc:ChargeIndicator>{value}</cbc:ChargeIndicator></cac:AllowanceCharge>"
                )
            ),
            Err(FailureKind::InvalidBoolean)
        );
    }
}
#[test]
fn nonnegative_amounts_preserve_double_comparison_and_outside_scope_exception() {
    for (value, result) in [
        ("", Ok(true)),
        ("0", Ok(true)),
        ("-0", Ok(true)),
        ("1e2", Ok(true)),
        ("INF", Ok(true)),
        ("NaN", Ok(false)),
        ("-1", Ok(false)),
        ("bad", Err(FailureKind::InvalidDouble)),
    ] {
        assert_eq!(
            run(
                K::Nonnegative,
                &format!(
                    "<cac:InvoiceLine><cac:Price><cbc:PriceAmount>{value}</cbc:PriceAmount></cac:Price></cac:InvoiceLine>"
                )
            ),
            result.map(|v| vec![v])
        );
    }
    for (code, expected) in [("O", vec![]), (" O ", vec![]), ("S", vec![false])] {
        assert_eq!(
            run(
                K::Nonnegative,
                &format!(
                    "<cac:TaxTotal><cac:TaxSubtotal><cbc:TaxableAmount>-1</cbc:TaxableAmount><cac:TaxCategory><cbc:ID>{code}</cbc:ID></cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal>"
                )
            ),
            Ok(expected)
        );
    }
    assert_eq!(
        run(
            K::Nonnegative,
            "<cac:LegalMonetaryTotal><cbc:PayableAmount>-1</cbc:PayableAmount><cbc:PayableRoundingAmount>-1</cbc:PayableRoundingAmount></cac:LegalMonetaryTotal><cac:InvoiceLine><cbc:LineExtensionAmount>-1</cbc:LineExtensionAmount></cac:InvoiceLine>"
        ),
        Ok(vec![])
    );
}
