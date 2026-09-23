//! Exact decimal operations used by the selected XPath predicates.
//! Rounding follows XPath 2.0 fn:round (ties toward positive infinity), not the
//! invoice builder's monetary rounding. XML lexical scale lives in XmlView.
use super::{FailureKind, xml::is_xml_space};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};

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

    pub fn add(&self, other: &Self, digits: usize) -> Result<Self, FailureKind> {
        let scale = self.scale.max(other.scale);
        let ten = BigInt::from(10);
        let a = &self.coefficient * ten.pow(scale - self.scale);
        let b = &other.coefficient * ten.pow(scale - other.scale);
        let result = Self::normalized(a + b, scale);
        if result
            .coefficient
            .to_str_radix(10)
            .trim_start_matches('-')
            .len()
            .max(result.scale as usize)
            > digits
        {
            return Err(FailureKind::Limit("decimal digits"));
        }
        Ok(result)
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
