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
