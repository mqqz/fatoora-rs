use super::{
    FailureKind, Limits,
    ksa_arithmetic::KsaArithmeticCheck as K,
    xml::{CAC, CBC, UBL, XmlView},
};
fn run(check: K, body: &str) -> Result<Vec<bool>, FailureKind> {
    let xml = XmlView::parse(
        &format!("<Invoice xmlns='{UBL}' xmlns:cac='{CAC}' xmlns:cbc='{CBC}'>{body}</Invoice>"),
        &Limits::default(),
    )
    .unwrap();
    check
        .contexts(&xml)
        .into_iter()
        .map(|n| check.passes(&xml, n, 4096))
        .collect()
}
#[test]
fn inclusive_line_total_uses_double_rounding_and_formatted_equality() {
    for (tax, net, total, expected) in [
        ("45", "300", "345.005", true),
        ("45", "300", "345.015", false),
        ("0", "1.005", "1.00", true),
        ("0", "2.675", "2.68", true),
    ] {
        assert_eq!(
            run(
                K::LineInclusive,
                &format!(
                    "<cac:InvoiceLine><cbc:LineExtensionAmount>{net}</cbc:LineExtensionAmount><cac:TaxTotal><cbc:TaxAmount>{tax}</cbc:TaxAmount><cbc:RoundingAmount>{total}</cbc:RoundingAmount></cac:TaxTotal></cac:InvoiceLine>"
                )
            ),
            Ok(vec![expected])
        );
    }
    assert_eq!(
        run(
            K::LineInclusive,
            "<cac:InvoiceLine><cac:TaxTotal/></cac:InvoiceLine>"
        ),
        Ok(vec![true])
    );
}
#[test]
fn foreign_currency_compares_rounded_totals_only_when_both_are_positive() {
    for (code, bare, expected) in [
        ("SAR", "100", true),
        ("USD", "100.004", false),
        ("USD", "100.006", true),
        ("USD", "0", true),
        (" USD ", "100", false),
    ] {
        assert_eq!(
            run(
                K::ForeignTax,
                &format!(
                    "<cbc:DocumentCurrencyCode>{code}</cbc:DocumentCurrencyCode><cac:TaxTotal><cbc:TaxAmount>{bare}</cbc:TaxAmount></cac:TaxTotal><cac:TaxTotal><cbc:TaxAmount>100</cbc:TaxAmount><cac:TaxSubtotal/></cac:TaxTotal>"
                )
            ),
            Ok(vec![expected])
        );
    }
}
#[test]
fn adjustment_calculation_preserves_double_floor_and_missing_percentage() {
    for (base, amount, expected) in [
        ("1.005", "1.00", true),
        ("1.005", "1.01", false),
        ("2.675", "2.68", true),
        ("-1.005", "-1.00", true),
    ] {
        assert_eq!(
            run(
                K::Adjustment,
                &format!(
                    "<cac:AllowanceCharge><cbc:MultiplierFactorNumeric>100</cbc:MultiplierFactorNumeric><cbc:Amount>{amount}</cbc:Amount><cbc:BaseAmount>{base}</cbc:BaseAmount></cac:AllowanceCharge>"
                )
            ),
            Ok(vec![expected])
        );
    }
    assert_eq!(
        run(
            K::Adjustment,
            "<cac:AllowanceCharge><cbc:Amount>1</cbc:Amount><cbc:BaseAmount>1</cbc:BaseAmount></cac:AllowanceCharge>"
        ),
        Ok(vec![false])
    );
    assert_eq!(
        run(
            K::Adjustment,
            "<cac:AllowanceCharge><cbc:BaseAmount>1</cbc:BaseAmount></cac:AllowanceCharge>"
        ),
        Ok(vec![])
    );
    assert_eq!(
        run(
            K::Adjustment,
            "<cac:AllowanceCharge><cbc:BaseAmount>1</cbc:BaseAmount></cac:AllowanceCharge><cac:AllowanceCharge><cbc:Amount>1</cbc:Amount></cac:AllowanceCharge>"
        ),
        Ok(vec![true])
    );
}
fn line(quantity: &str, price: &str, base: Option<&str>, net: &str, adjustments: &str) -> String {
    let base = base
        .map(|v| format!("<cbc:BaseQuantity>{v}</cbc:BaseQuantity>"))
        .unwrap_or_default();
    format!(
        "<cac:InvoiceLine><cbc:InvoicedQuantity>{quantity}</cbc:InvoicedQuantity><cbc:LineExtensionAmount>{net}</cbc:LineExtensionAmount>{adjustments}<cac:Price><cbc:PriceAmount>{price}</cbc:PriceAmount>{base}</cac:Price></cac:InvoiceLine>"
    )
}
#[test]
fn line_net_rounds_after_mill_precision_and_accepts_only_one_cent_tolerance() {
    for (net, expected) in [
        ("299.98", false),
        ("299.99", true),
        ("300", true),
        ("300.01", true),
        ("300.02", false),
    ] {
        assert_eq!(
            run(K::LineNet, &line("2", "150", None, net, "")),
            Ok(vec![expected])
        );
        assert_eq!(
            run(K::LineNet, &line("4", "150", Some("2"), net, "")),
            Ok(vec![expected])
        );
    }
    let adjustments = "<cac:AllowanceCharge><cbc:ChargeIndicator>true</cbc:ChargeIndicator><cbc:Amount>3.25</cbc:Amount></cac:AllowanceCharge><cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:Amount>1.10</cbc:Amount></cac:AllowanceCharge>";
    assert_eq!(
        run(K::LineNet, &line("2", "150", None, "302.15", adjustments)),
        Ok(vec![true])
    );
    assert_eq!(
        run(K::LineNet, &line("1", "1.005", None, "1.01", "")),
        Ok(vec![true])
    );
    assert_eq!(
        run(K::LineNet, &line("1", "1", Some("0"), "0", "")),
        Err(FailureKind::DivisionByZero)
    );
}
#[test]
fn line_net_retains_sdk_division_precision_before_multiplication() {
    for (price, divisor, net, expected) in [
        ("1", "3", "33333333333333333300", true),
        ("1", "3", "33333333333333333333.33", false),
        ("3", "524288", "572204589843700", true),
        ("3", "524288", "572204589843800", false),
    ] {
        assert_eq!(
            run(
                K::LineNet,
                &line("100000000000000000000", price, Some(divisor), net, "")
            ),
            Ok(vec![expected])
        );
    }
}

#[test]
fn missing_line_operands_short_circuit_later_casts_and_adjustments_are_singletons() {
    for body in [
        "<cac:InvoiceLine><cbc:InvoicedQuantity>1E0</cbc:InvoicedQuantity></cac:InvoiceLine>",
        "<cac:InvoiceLine><cbc:LineExtensionAmount>1</cbc:LineExtensionAmount><cac:Price><cbc:PriceAmount>1</cbc:PriceAmount><cbc:BaseQuantity>0</cbc:BaseQuantity></cac:Price></cac:InvoiceLine>",
        "<cac:InvoiceLine><cbc:LineExtensionAmount>1</cbc:LineExtensionAmount><cbc:InvoicedQuantity>1</cbc:InvoicedQuantity><cac:Price><cbc:BaseQuantity>1E0</cbc:BaseQuantity></cac:Price></cac:InvoiceLine>",
    ] {
        assert_eq!(run(K::LineNet, body), Ok(vec![false]));
    }
    let adjustments = "<cac:AllowanceCharge><cbc:ChargeIndicator>true</cbc:ChargeIndicator><cbc:Amount>1</cbc:Amount><cbc:Amount>2</cbc:Amount></cac:AllowanceCharge>";
    assert_eq!(
        run(K::LineNet, &line("1", "1", None, "4", adjustments)),
        Err(FailureKind::Cardinality)
    );
}
