//! Reference arithmetic uses unbounded integers; production uses checked i128.
use super::*;
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use proptest::prelude::*;

fn literal(coefficient: i128, scale: u32) -> String {
    let sign = if coefficient < 0 { "-" } else { "" };
    let digits = format!("{:0width$}", coefficient.abs(), width = scale as usize + 1);
    if scale == 0 {
        return format!("{sign}{digits}");
    }
    let at = digits.len() - scale as usize;
    format!("{sign}{}.{}", &digits[..at], &digits[at..])
}

fn canonical(mut coefficient: BigInt, mut scale: u32) -> String {
    while scale > 0 && (&coefficient % 10u8).is_zero() {
        coefficient /= 10u8;
        scale -= 1;
    }
    let sign = if coefficient.is_negative() { "-" } else { "" };
    let mut digits = coefficient.abs().to_string();
    if scale == 0 {
        return format!("{sign}{digits}");
    }
    if digits.len() <= scale as usize {
        digits = format!(
            "{}{}",
            "0".repeat(scale as usize + 1 - digits.len()),
            digits
        );
    }
    let at = digits.len() - scale as usize;
    format!("{sign}{}.{}", &digits[..at], &digits[at..])
}

// Nearest integer cents, with exact half cents rounded away from zero.
fn reference_cents(coefficient: BigInt, scale: u32) -> String {
    let numerator = coefficient.abs() * 100u8;
    let denominator = BigInt::from(10u8).pow(scale);
    let magnitude = (numerator * 2u8 + &denominator) / (denominator * 2u8);
    canonical(
        if coefficient.is_negative() {
            -magnitude
        } else {
            magnitude
        },
        2,
    )
}

fn operand() -> impl Strategy<Value = (i128, u32)> {
    (
        prop_oneof![
            Just(0),
            Just(1),
            Just(-1),
            -1_000_000_000i128..=1_000_000_000
        ],
        0u32..=28,
    )
}

proptest! {
    #[test]
    fn property_decimal_text_and_json_are_exact((coefficient, scale) in operand()) {
        let value = Decimal::parse(&literal(coefficient, scale)).unwrap();
        let expected = canonical(BigInt::from(coefficient), scale);
        prop_assert_eq!(value.to_string(), expected.as_str());
        prop_assert_eq!(serde_json::to_value(value).unwrap(), serde_json::json!(expected));
        prop_assert_eq!(serde_json::from_str::<Decimal>(&serde_json::to_string(&value).unwrap()).unwrap(), value);
    }

    #[test]
    fn property_addition_and_subtraction_match_exact_integers(a in operand(), b in operand()) {
        let lhs = Decimal::parse(&literal(a.0, a.1)).unwrap();
        let rhs = Decimal::parse(&literal(b.0, b.1)).unwrap();
        let scale = a.1.max(b.1);
        let x = BigInt::from(a.0) * BigInt::from(10u8).pow(scale - a.1);
        let y = BigInt::from(b.0) * BigInt::from(10u8).pow(scale - b.1);
        for (actual, expected) in [(lhs.add(rhs), &x + &y), (lhs.sub(rhs), &x - &y)] {
            // These generators keep aligned intermediates inside i128. Any
            // failure must be the 96-bit result limit, not precision loss.
            let text = canonical(expected, scale);
            let coefficient = text.replace(['-', '.'], "").parse::<BigInt>().unwrap();
            if coefficient > (BigInt::from(1u8) << 96) - 1u8 {
                prop_assert_eq!(actual, Err(DecimalError::OutOfRange));
            } else {
                prop_assert_eq!(actual.unwrap().to_string(), text);
            }
        }
    }

    #[test]
    fn property_products_round_once_against_integer_oracle(a in operand(), b in operand(), percent in any::<bool>()) {
        let lhs = Decimal::parse(&literal(a.0, a.1)).unwrap();
        let rhs = Decimal::parse(&literal(b.0, b.1)).unwrap();
        let expected = reference_cents(BigInt::from(a.0) * b.0, a.1 + b.1 + if percent { 2 } else { 0 });
        prop_assert_eq!(lhs.product_rounded(rhs, percent).unwrap().to_string(), expected);
    }

    #[test]
    fn property_line_vat_rounds_after_all_three_factors(a in operand(), b in operand(), rate in 0i128..=100, rate_scale in 0u32..=2) {
        let quantity = Decimal::parse(&literal(a.0, a.1)).unwrap();
        let price = Decimal::parse(&literal(b.0, b.1)).unwrap();
        let tax = Decimal::parse(&literal(rate, rate_scale)).unwrap();
        let expected = reference_cents(BigInt::from(a.0) * b.0 * rate, a.1 + b.1 + rate_scale + 2);
        prop_assert_eq!(quantity.line_vat(price, tax).unwrap().to_string(), expected);
    }

    #[test]
    fn property_96_bit_result_boundary_is_exact(distance in 0i128..=10_000, increment in 0i128..=20_000, negative in any::<bool>()) {
        let max = (1i128 << 96) - 1;
        let sign = if negative { -1 } else { 1 };
        let lhs = Decimal::parse(&(sign * (max - distance)).to_string()).unwrap();
        let rhs = Decimal::parse(&(sign * increment).to_string()).unwrap();
        if increment > distance {
            prop_assert_eq!(lhs.add(rhs), Err(DecimalError::OutOfRange));
        } else {
            prop_assert_eq!(lhs.add(rhs).unwrap().to_string(), (sign * (max - distance + increment)).to_string());
        }
        prop_assert_eq!(lhs.product_rounded(Decimal::from(2), false), Err(DecimalError::OutOfRange));
    }

    #[test]
    fn property_half_cent_neighbors_round_away_from_zero(cents in -1_000_000i128..=1_000_000, below in -1i128..=1) {
        let coefficient = cents * 1000 + 500 + below;
        let value = Decimal::parse(&literal(coefficient, 5)).unwrap();
        prop_assert_eq!(value.product_rounded(Decimal::from(1), false).unwrap().to_string(), reference_cents(BigInt::from(coefficient), 5));
    }
}
