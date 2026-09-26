//! Exact decimal input and deterministic invoice arithmetic.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

/// A crate-owned decimal: a signed 96-bit coefficient and scale 0 through 28.
/// Parsing is exact. JSON represents decimals as strings, never binary floats.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Decimal(rust_decimal::Decimal);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecimalError {
    #[error("expected decimal notation with digits before and after any decimal point")]
    InvalidSyntax,
    #[error("decimal precision or range exceeded")]
    OutOfRange,
}

impl DecimalError {
    /// Shared classification used by bindings.
    pub fn kind(&self) -> crate::ErrorKind {
        crate::ErrorKind::InvalidInput
    }
}
impl Decimal {
    pub const ZERO: Self = Self(rust_decimal::Decimal::ZERO);
    pub fn parse(value: &str) -> Result<Self, DecimalError> {
        value.parse()
    }
    pub(crate) fn scale(self) -> u32 {
        self.0.normalize().scale()
    }
    pub(crate) fn fixed(self, precision: usize) -> String {
        format!("{:.*}", precision, self.0)
    }
    pub(crate) fn add(self, other: Self) -> Result<Self, DecimalError> {
        // Equalize coefficients ourselves: the backing crate may otherwise reduce precision.
        let scale = self.0.scale().max(other.0.scale());
        let a = self
            .0
            .mantissa()
            .checked_mul(10i128.pow(scale - self.0.scale()))
            .ok_or(DecimalError::OutOfRange)?;
        let b = other
            .0
            .mantissa()
            .checked_mul(10i128.pow(scale - other.0.scale()))
            .ok_or(DecimalError::OutOfRange)?;
        Self::coefficient(a.checked_add(b).ok_or(DecimalError::OutOfRange)?, scale)
    }
    pub(crate) fn sub(self, other: Self) -> Result<Self, DecimalError> {
        self.add(Self(-other.0))
    }
    fn coefficient(mut value: i128, mut scale: u32) -> Result<Self, DecimalError> {
        while scale > 0 && value % 10 == 0 {
            value /= 10;
            scale -= 1;
        }
        rust_decimal::Decimal::try_from_i128_with_scale(value, scale)
            .map(Self)
            .map_err(|_| DecimalError::OutOfRange)
    }
    /// One final rounding operation, with exact checked integer intermediates.
    pub(crate) fn product_rounded(self, other: Self, percent: bool) -> Result<Self, DecimalError> {
        let a = self.0.normalize();
        let b = other.0.normalize();
        let coefficient = a
            .mantissa()
            .checked_mul(b.mantissa())
            .ok_or(DecimalError::OutOfRange)?;
        Self::round_coefficient(
            coefficient,
            a.scale() + b.scale() + if percent { 2 } else { 0 },
            2,
        )
    }
    pub(crate) fn line_vat(self, price: Self, rate: Self) -> Result<Self, DecimalError> {
        let a = self.0.normalize();
        let b = price.0.normalize();
        let c = rate.0.normalize();
        let coefficient = a
            .mantissa()
            .checked_mul(b.mantissa())
            .and_then(|v| v.checked_mul(c.mantissa()))
            .ok_or(DecimalError::OutOfRange)?;
        Self::round_coefficient(coefficient, a.scale() + b.scale() + c.scale() + 2, 2)
    }
    fn round_coefficient(value: i128, scale: u32, places: u32) -> Result<Self, DecimalError> {
        if scale <= places {
            return Self::coefficient(value, scale);
        }
        let difference = scale - places;
        if difference > 38 {
            return Ok(Self::ZERO);
        }
        let divisor = 10i128.pow(difference);
        let quotient = value / divisor;
        let remainder = value % divisor;
        let rounded = quotient
            + if remainder.abs() >= divisor / 2 {
                value.signum()
            } else {
                0
            };
        Self::coefficient(rounded, places)
    }
    #[cfg(test)]
    fn round(self, places: u32) -> Self {
        Self::round_coefficient(self.0.mantissa(), self.0.scale(), places).unwrap()
    }
}
impl FromStr for Decimal {
    type Err = DecimalError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let unsigned = value
            .strip_prefix('-')
            .or_else(|| value.strip_prefix('+'))
            .unwrap_or(value);
        let mut parts = unsigned.split('.');
        let integer = parts.next().unwrap_or("");
        let fraction = parts.next();
        if integer.is_empty()
            || !integer.bytes().all(|b| b.is_ascii_digit())
            || parts.next().is_some()
            || fraction.is_some_and(|v| v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(DecimalError::InvalidSyntax);
        }
        rust_decimal::Decimal::from_str_exact(value)
            .map(|v| Self(v.normalize()))
            .map_err(|_| DecimalError::OutOfRange)
    }
}
impl From<i64> for Decimal {
    fn from(value: i64) -> Self {
        Self(value.into())
    }
}
impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.normalize().fmt(f)
    }
}
impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zatca_rounding_examples() {
        for (input, places, expected) in [
            ("123.4949", 2, "123.49"),
            ("123.4951", 2, "123.50"),
            ("123.49494999", 4, "123.4949"),
            ("123.49495001", 4, "123.4950"),
            ("1.005", 2, "1.01"),
            ("1.025", 2, "1.03"),
            ("1.0049", 2, "1.00"),
        ] {
            assert_eq!(
                Decimal::parse(input).unwrap().round(places),
                Decimal::parse(expected).unwrap()
            );
        }
    }
}

#[cfg(test)]
#[path = "decimal_properties.rs"]
mod properties;
