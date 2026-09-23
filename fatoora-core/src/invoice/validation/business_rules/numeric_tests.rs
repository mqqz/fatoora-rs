//! Independent XPath 2.0 / XML Schema numeric contracts.
//! https://www.w3.org/TR/2010/REC-xpath-functions-20101214/#func-round
use super::{
    FailureKind,
    decimal::{ExactDecimal, parse_double, round_double},
};

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value, 4096).unwrap()
}

#[test]
fn decimal_syntax_and_exact_arithmetic_do_not_use_model_normalization() {
    for (input, expected) in [
        (" +.5\t", "0.5"),
        ("1.", "1"),
        ("-0.000", "0"),
        ("0001.200", "1.2"),
    ] {
        assert_eq!(decimal(input), decimal(expected), "{input}");
    }
    for invalid in [
        "", " ", ".", "+", "1e2", "NaN", "INF", "1 2", "1..2", "١", "\u{a0}1", "1\u{a0}",
    ] {
        assert_eq!(
            ExactDecimal::parse(invalid, 4096),
            Err(FailureKind::InvalidDecimal),
            "{invalid:?}"
        );
    }
    assert_eq!(
        decimal("0.1").add(&decimal("0.2"), 4096).unwrap(),
        decimal("0.3")
    );
    assert_eq!(
        decimal("1.000000000000000000000000000000000000001")
            .add(&decimal("-1"), 4096)
            .unwrap(),
        decimal("0.000000000000000000000000000000000000001")
    );
    let large = "9999999999999999999999999999999999999999999999999999999999999999";
    assert_eq!(
        decimal(large).add(&decimal("1"), 4096).unwrap(),
        decimal(&format!("1{}", "0".repeat(large.len())))
    );
}

#[test]
fn xpath_decimal_rounding_ties_toward_positive_infinity() {
    for (input, expected) in [
        ("1.005", "1.01"),
        ("-1.005", "-1.00"),
        ("-1.015", "-1.01"),
        ("-0.005", "0"),
        ("-0.0051", "-0.01"),
        ("1.0049", "1.00"),
    ] {
        assert_eq!(decimal(input).round(2), decimal(expected), "{input}");
    }
}

#[test]
fn precision_limits_fail_instead_of_rounding_or_overflowing() {
    assert_eq!(
        ExactDecimal::parse("12345", 4),
        Err(FailureKind::Limit("decimal digits"))
    );
    assert_eq!(
        decimal("9999").add(&decimal("1"), 4),
        Err(FailureKind::Limit("decimal digits"))
    );
    assert_eq!(
        ExactDecimal::parse("0.00001", 4),
        Err(FailureKind::Limit("decimal digits"))
    );
}

#[test]
fn explicit_double_operations_remain_distinct() {
    assert_ne!(
        parse_double("0.1").unwrap() + parse_double("0.2").unwrap(),
        parse_double("0.3").unwrap()
    );
    assert_eq!(parse_double(" 1.25E2\n").unwrap(), 125.0);
    assert!(parse_double("NaN").unwrap().is_nan());
    assert_eq!(parse_double("INF").unwrap(), f64::INFINITY);
    assert_eq!(parse_double("-INF").unwrap(), f64::NEG_INFINITY);
    for invalid in ["inf", "+INF", "nan", "1_0", "\u{a0}1"] {
        assert_eq!(parse_double(invalid), Err(FailureKind::InvalidDouble));
    }
    assert_eq!(round_double(-1.5), -1.0);
    assert!(round_double(-0.5).is_sign_negative());
    assert_eq!(round_double(-0.5), 0.0);
    assert!(round_double(f64::NAN).is_nan());
    assert_eq!(round_double(f64::INFINITY), f64::INFINITY);
    assert_eq!(round_double(4503599627370497.0), 4503599627370497.0);
}

#[test]
fn exact_subtraction_and_multiplication_preserve_mixed_scales_and_signs() {
    for (left, right, difference, product) in [
        ("5.20", "1.005", "4.195", "5.226"),
        ("-1.25", "-2.125", "0.875", "2.65625"),
        ("-12.50", "0.08", "-12.58", "-1"),
        ("0.125", "0.8", "-0.675", "0.1"),
        ("0", "-1.20", "1.2", "0"),
    ] {
        assert_eq!(
            decimal(left).subtract(&decimal(right), 4096).unwrap(),
            decimal(difference),
            "{left} - {right}"
        );
        assert_eq!(
            decimal(left).multiply(&decimal(right), 4096).unwrap(),
            decimal(product),
            "{left} * {right}"
        );
    }
    let precise = decimal("1.000000000000000000000000000000000000001");
    assert_eq!(
        precise.subtract(&decimal("1"), 4096).unwrap(),
        decimal("0.000000000000000000000000000000000000001")
    );
    assert_eq!(precise.subtract(&precise, 1).unwrap(), decimal("0"));
    assert_eq!(precise.multiply(&decimal("0"), 1).unwrap(), decimal("0"));
}

#[test]
fn numeric_ordering_compares_values_across_scales_and_signs() {
    let inputs = [
        "10", "-0.0001", "-100", "0.1", "-10.01", "2", "0", "-10", "0.00001",
    ];
    let mut actual: Vec<_> = inputs.into_iter().map(decimal).collect();
    actual.sort();
    let expected: Vec<_> = [
        "-100", "-10.01", "-10", "-0.0001", "0", "0.00001", "0.1", "2", "10",
    ]
    .into_iter()
    .map(decimal)
    .collect();
    assert_eq!(actual, expected);
    assert_eq!(
        decimal("001.2000").cmp(&decimal("1.2")),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        decimal("-0.000").partial_cmp(&decimal("0")),
        Some(std::cmp::Ordering::Equal)
    );
    assert!(decimal("9.99") < decimal("10"));
    assert!(decimal("-9.99") > decimal("-10"));
}

#[test]
fn integer_construction_absolute_value_and_floor_are_exact() {
    for value in [i64::MIN, -1, 0, 1, i64::MAX] {
        assert_eq!(ExactDecimal::from_i64(value), decimal(&value.to_string()));
    }
    for (value, absolute, floored) in [
        ("12.125", "12.125", "12"),
        ("-12.125", "12.125", "-13"),
        ("-0.0001", "0.0001", "-1"),
        ("0.0001", "0.0001", "0"),
        ("-12", "12", "-12"),
        ("-0.00", "0", "0"),
    ] {
        assert_eq!(decimal(value).abs(), decimal(absolute));
        assert_eq!(decimal(value).floor(), decimal(floored));
    }
}

#[test]
fn decimal_scale_down_divides_exactly_by_powers_of_ten() {
    for (value, places, expected) in [
        ("123.45", 0, "123.45"),
        ("123.45", 2, "1.2345"),
        ("-12.5", 3, "-0.0125"),
        ("1000", 3, "1"),
        ("1000", 4, "0.1"),
        ("-100", 1, "-10"),
        ("0", u32::MAX, "0"),
    ] {
        assert_eq!(
            decimal(value).scale_down(places, 4096).unwrap(),
            decimal(expected)
        );
    }
}

#[test]
fn half_even_rounding_handles_both_tie_directions_and_negative_values() {
    for (value, places, expected) in [
        ("1.005", 2, "1"),
        ("1.015", 2, "1.02"),
        ("-1.005", 2, "-1"),
        ("-1.015", 2, "-1.02"),
        ("2.5", 0, "2"),
        ("3.5", 0, "4"),
        ("-2.5", 0, "-2"),
        ("-3.5", 0, "-4"),
        ("0.005", 2, "0"),
        ("-0.005", 2, "0"),
        ("199.995", 2, "200"),
        ("-199.995", 2, "-200"),
        ("1.0051", 2, "1.01"),
        ("-1.0051", 2, "-1.01"),
        ("1.0049", 2, "1"),
        ("-1.0049", 2, "-1"),
        ("1.2", 4, "1.2"),
    ] {
        assert_eq!(
            decimal(value).round_half_even(places),
            decimal(expected),
            "{value}"
        );
    }
    assert_ne!(
        decimal("1.005").round_half_even(2),
        decimal("1.005").round(2)
    );
}

#[test]
fn decimal_result_budgets_reject_growth_but_allow_normalized_cancellation() {
    let maximum = decimal(&"9".repeat(4096));
    for result in [
        maximum.subtract(&decimal("-1"), 4096),
        maximum.multiply(&decimal("10"), 4096),
        decimal("0.1").scale_down(4096, 4096),
        decimal("0.1").scale_down(u32::MAX, 4096),
        decimal("1").scale_down(u32::MAX, 4096),
    ] {
        assert_eq!(result, Err(FailureKind::Limit("decimal digits")));
    }
    assert_eq!(maximum.subtract(&maximum, 1).unwrap(), decimal("0"));
    assert_eq!(maximum.multiply(&decimal("0"), 1).unwrap(), decimal("0"));
    let power = decimal(&format!("1{}", "0".repeat(4095)));
    assert_eq!(power.scale_down(4096, 1).unwrap(), decimal("0.1"));
    assert_eq!(
        decimal("0.2").multiply(&decimal("0.5"), 1).unwrap(),
        decimal("0.1")
    );
    assert_eq!(
        decimal("1").scale_down(4096, 4096).unwrap(),
        decimal("0.1").scale_down(4095, 4096).unwrap()
    );
    assert_eq!(maximum.multiply(&decimal("1"), 4096).unwrap(), maximum);
}

#[test]
fn double_to_decimal_cast_preserves_binary_value_before_rounding() {
    assert_eq!(
        ExactDecimal::from_double(0.1, 4096).unwrap(),
        decimal("0.1000000000000000055511151231257827021181583404541015625")
    );
    for (value, expected) in [
        (1.005, "1.00"),
        (-1.005, "-1.00"),
        (2.675, "2.67"),
        (1000000000000000100.0, "1000000000000000128"),
    ] {
        assert_eq!(
            ExactDecimal::from_double(value, 4096).unwrap().round(2),
            decimal(expected)
        );
    }
    assert_eq!(ExactDecimal::from_double(-0.0, 4096).unwrap(), decimal("0"));
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            ExactDecimal::from_double(value, 4096),
            Err(FailureKind::InvalidDecimal)
        );
    }
    assert_eq!(
        ExactDecimal::from_double(0.1, 2),
        Err(FailureKind::Limit("decimal digits"))
    );
    assert!(ExactDecimal::from_double(f64::from_bits(1), 4096).unwrap() > decimal("0"));
    assert!(ExactDecimal::from_double(f64::MAX, 4096).is_ok());
}
