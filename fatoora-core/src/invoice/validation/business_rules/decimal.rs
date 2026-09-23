//! Exact decimal operations used by the selected XPath predicates.
//! Rounding follows XPath 2.0 fn:round (ties toward positive infinity), not the
//! invoice builder's monetary rounding. XML lexical scale lives in XmlView.
use super::{FailureKind, xml::is_xml_space};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExactDecimal {
    coefficient: BigInt,
    scale: u32,
}

impl ExactDecimal {
    pub fn zero() -> Self {
        Self {
            coefficient: BigInt::zero(),
            scale: 0,
        }
    }

    pub fn from_i64(value: i64) -> Self {
        Self {
            coefficient: BigInt::from(value),
            scale: 0,
        }
    }

    /// Convert the complete decimal value in one correctly rounded operation.
    /// Separately converting coefficient and scale can overflow before division.
    pub fn to_double(&self) -> f64 {
        format!("{}e-{}", self.coefficient, self.scale)
            .parse()
            .expect("integer coefficient and decimal scale form a valid double")
    }

    /// Cast the actual binary value, never its shortest display representation.
    pub fn from_double(value: f64, digits: usize) -> Result<Self, FailureKind> {
        if !value.is_finite() {
            return Err(FailureKind::InvalidDecimal);
        }
        if value == 0.0 {
            return Self::zero().bounded(digits);
        }
        let bits = value.to_bits();
        let fraction = bits & ((1u64 << 52) - 1);
        let exponent = ((bits >> 52) & 0x7ff) as i32;
        let (mantissa, exponent) = if exponent == 0 {
            (fraction, -1074)
        } else {
            (fraction | (1u64 << 52), exponent - 1023 - 52)
        };
        let mut coefficient = BigInt::from(mantissa);
        let scale = if exponent < 0 {
            coefficient *= BigInt::from(5u8).pow((-exponent) as u32);
            (-exponent) as u32
        } else {
            coefficient <<= exponent as usize;
            0
        };
        if value.is_sign_negative() {
            coefficient = -coefficient;
        }
        Self::normalized(coefficient, scale).bounded(digits)
    }

    pub fn parse(input: &str, digits: usize) -> Result<Self, FailureKind> {
        let value = input.trim_matches(is_xml_space);
        let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
        if !decimal_syntax(unsigned) {
            return Err(FailureKind::InvalidDecimal);
        }
        let count = unsigned.bytes().filter(u8::is_ascii_digit).count();
        if count > digits {
            return Err(FailureKind::Limit("decimal digits"));
        }
        let scale = unsigned.split_once('.').map_or(0, |(_, f)| f.len());
        let scale = u32::try_from(scale).map_err(|_| FailureKind::Limit("decimal digits"))?;
        let coefficient = BigInt::parse_bytes(value.replace('.', "").as_bytes(), 10)
            .ok_or(FailureKind::InvalidDecimal)?;
        Ok(Self::normalized(coefficient, scale))
    }

    fn normalized(mut coefficient: BigInt, mut scale: u32) -> Self {
        if coefficient.is_zero() {
            return Self::zero();
        }
        while scale > 0 && (&coefficient % 10u8).is_zero() {
            coefficient /= 10u8;
            scale -= 1;
        }
        Self { coefficient, scale }
    }

    fn bounded(self, digits: usize) -> Result<Self, FailureKind> {
        if self
            .coefficient
            .to_str_radix(10)
            .trim_start_matches('-')
            .len()
            .max(self.scale as usize)
            > digits
        {
            return Err(FailureKind::Limit("decimal digits"));
        }
        Ok(self)
    }

    fn aligned_coefficients(&self, other: &Self) -> (BigInt, BigInt, u32) {
        let scale = self.scale.max(other.scale);
        let ten = BigInt::from(10);
        let a = &self.coefficient * ten.pow(scale - self.scale);
        let b = &other.coefficient * ten.pow(scale - other.scale);
        (a, b, scale)
    }

    pub fn add(&self, other: &Self, digits: usize) -> Result<Self, FailureKind> {
        let (a, b, scale) = self.aligned_coefficients(other);
        Self::normalized(a + b, scale).bounded(digits)
    }

    pub fn subtract(&self, other: &Self, digits: usize) -> Result<Self, FailureKind> {
        let (a, b, scale) = self.aligned_coefficients(other);
        Self::normalized(a - b, scale).bounded(digits)
    }

    pub fn multiply(&self, other: &Self, digits: usize) -> Result<Self, FailureKind> {
        if self.coefficient.is_zero() || other.coefficient.is_zero() {
            return Self::zero().bounded(digits);
        }
        let scale = self
            .scale
            .checked_add(other.scale)
            .ok_or(FailureKind::Limit("decimal digits"))?;
        Self::normalized(&self.coefficient * &other.coefficient, scale).bounded(digits)
    }

    /// Decimal division used by the pinned SDK's line-net calculation.
    /// Independent CLI probes establish a minimum scale of 18, adjusted by
    /// normalized operand scales, with midpoint rounding toward zero. Integer
    /// trailing zeroes matter: 3e20 has normalized scale -20; 3e20+1 has 0.
    pub fn divide_sdk(&self, other: &Self, digits: usize) -> Result<Self, FailureKind> {
        if other.coefficient.is_zero() {
            return Err(FailureKind::DivisionByZero);
        }
        if self.coefficient.is_zero() {
            return Self::zero().bounded(digits);
        }
        let normalized_scale = |value: &Self| {
            let coefficient = value.coefficient.to_str_radix(10);
            value.scale as i64
                - (coefficient.len() - coefficient.trim_end_matches('0').len()) as i64
        };
        let scale = 18.max(18 + normalized_scale(self) - normalized_scale(other));
        let scale = u32::try_from(scale).map_err(|_| FailureKind::Limit("decimal digits"))?;
        let exponent = other.scale as i64 + scale as i64 - self.scale as i64;
        let (numerator, denominator) = if exponent >= 0 {
            (
                &self.coefficient * BigInt::from(10u8).pow(exponent as u32),
                other.coefficient.clone(),
            )
        } else {
            (
                self.coefficient.clone(),
                &other.coefficient * BigInt::from(10u8).pow((-exponent) as u32),
            )
        };
        let mut quotient = &numerator / &denominator;
        let remainder = &numerator % &denominator;
        if remainder.abs() * 2u8 > denominator.abs() {
            quotient += if numerator.is_negative() == denominator.is_negative() {
                1
            } else {
                -1
            };
        }
        Self::normalized(quotient, scale).bounded(digits)
    }

    #[cfg(test)]
    pub fn abs(&self) -> Self {
        Self {
            coefficient: self.coefficient.abs(),
            scale: self.scale,
        }
    }

    pub fn floor(&self) -> Self {
        if self.scale == 0 {
            return self.clone();
        }
        let divisor = BigInt::from(10).pow(self.scale);
        let mut quotient = &self.coefficient / &divisor;
        if self.coefficient.is_negative() && !(&self.coefficient % divisor).is_zero() {
            quotient -= 1;
        }
        Self::normalized(quotient, 0)
    }

    /// Divide exactly by 10^places, retaining all fractional digits.
    pub fn scale_down(&self, places: u32, digits: usize) -> Result<Self, FailureKind> {
        if self.coefficient.is_zero() {
            return Self::zero().bounded(digits);
        }
        let scale = self
            .scale
            .checked_add(places)
            .ok_or(FailureKind::Limit("decimal digits"))?;
        Self::normalized(self.coefficient.clone(), scale).bounded(digits)
    }

    /// Equivalent to round(value * 10^places) div 10^places for decimals.
    pub fn round(&self, places: u32) -> Self {
        if self.scale <= places {
            return self.clone();
        }
        let divisor = BigInt::from(10).pow(self.scale - places);
        let mut quotient = &self.coefficient / &divisor;
        let remainder = &self.coefficient % &divisor;
        let twice = remainder.abs() * 2u8;
        if (remainder.is_positive() && twice >= divisor)
            || (remainder.is_negative() && twice > divisor)
        {
            quotient += remainder.signum();
        }
        Self::normalized(quotient, places)
    }

    /// XPath fn:round-half-to-even, distinct from fn:round's midpoint rule.
    pub fn round_half_even(&self, places: u32) -> Self {
        if self.scale <= places {
            return self.clone();
        }
        let divisor = BigInt::from(10).pow(self.scale - places);
        let mut quotient = &self.coefficient / &divisor;
        let remainder = &self.coefficient % &divisor;
        let twice = remainder.abs() * 2u8;
        if twice > divisor || (twice == divisor && !(&quotient % 2u8).is_zero()) {
            quotient += remainder.signum();
        }
        Self::normalized(quotient, places)
    }
}

impl Ord for ExactDecimal {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.scale == other.scale {
            return self.coefficient.cmp(&other.coefficient);
        }
        let (a, b, _) = self.aligned_coefficients(other);
        a.cmp(&b)
    }
}

impl PartialOrd for ExactDecimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn decimal_syntax(value: &str) -> bool {
    let mut point = false;
    let mut digit = false;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            digit = true;
        } else if byte == b'.' && !point {
            point = true;
        } else {
            return false;
        }
    }
    digit
}

/// Explicit xs:double conversion; never used implicitly for decimal predicates.
pub(super) fn parse_double(input: &str) -> Result<f64, FailureKind> {
    let value = input.trim_matches(is_xml_space);
    match value {
        "INF" => return Ok(f64::INFINITY),
        "-INF" => return Ok(f64::NEG_INFINITY),
        "NaN" => return Ok(f64::NAN),
        _ => {}
    }
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    let (mantissa, exponent) = unsigned.find(['e', 'E']).map_or((unsigned, None), |i| {
        (&unsigned[..i], Some(&unsigned[i + 1..]))
    });
    if !decimal_syntax(mantissa)
        || exponent.is_some_and(|exponent| {
            let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
            exponent.is_empty() || !exponent.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err(FailureKind::InvalidDouble);
    }
    value.parse().map_err(|_| FailureKind::InvalidDouble)
}

pub(super) fn round_double(value: f64) -> f64 {
    if !value.is_finite() || value == 0.0 {
        return value;
    }
    if (-0.5..0.0).contains(&value) || value == -0.5 {
        return -0.0;
    }
    let floor = value.floor();
    if value - floor < 0.5 {
        floor
    } else {
        floor + 1.0
    }
}

/// Equality of format-number(..., '#.00') results without allocating their text.
/// A missing numeric operand formats as NaN; unlike numeric NaN, those strings
/// compare equal. The picture retains the minus sign when rounding to zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FormattedNumber {
    Finite(ExactDecimal, bool),
    NaN,
    Infinity(bool),
}
impl FormattedNumber {
    pub fn from_decimal(value: &ExactDecimal) -> Self {
        let rounded = value.round_half_even(2);
        let negative_zero = value < &ExactDecimal::zero() && rounded == ExactDecimal::zero();
        Self::Finite(rounded, negative_zero)
    }
    pub fn from_double(value: f64, digits: usize) -> Result<Self, FailureKind> {
        if value.is_nan() {
            return Ok(Self::NaN);
        }
        if value.is_infinite() {
            return Ok(Self::Infinity(value.is_sign_negative()));
        }
        let rounded = ExactDecimal::parse(&value.to_string(), digits)?.round_half_even(2);
        let negative_zero = value.is_sign_negative() && rounded == ExactDecimal::zero();
        Ok(Self::Finite(rounded, negative_zero))
    }
}
