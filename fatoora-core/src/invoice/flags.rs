//! Invoice flags with a crate-owned public surface.
use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    struct FlagBits: u8 {
        const THIRD_PARTY = 0b00001;
        const NOMINAL = 0b00010;
        const EXPORT = 0b00100;
        const SUMMARY = 0b01000;
        const SELF_BILLED = 0b10000;
    }
}

/// Invoice boolean flags packed into a bitset.
///
/// ```
/// use fatoora_core::invoice::InvoiceFlags;
/// let flags = InvoiceFlags::EXPORT | InvoiceFlags::SELF_BILLED;
/// assert!(flags.contains(InvoiceFlags::EXPORT));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InvoiceFlags(FlagBits);

impl InvoiceFlags {
    pub const THIRD_PARTY: Self = Self(FlagBits::THIRD_PARTY);
    pub const NOMINAL: Self = Self(FlagBits::NOMINAL);
    pub const EXPORT: Self = Self(FlagBits::EXPORT);
    pub const SUMMARY: Self = Self(FlagBits::SUMMARY);
    pub const SELF_BILLED: Self = Self(FlagBits::SELF_BILLED);

    pub const fn empty() -> Self {
        Self(FlagBits::empty())
    }
    pub const fn all() -> Self {
        Self(FlagBits::all())
    }
    pub const fn bits(&self) -> u8 {
        self.0.bits()
    }
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match FlagBits::from_bits(bits) {
            Some(flags) => Some(Self(flags)),
            None => None,
        }
    }
    pub const fn from_bits_truncate(bits: u8) -> Self {
        Self(FlagBits::from_bits_truncate(bits))
    }
    pub const fn from_bits_retain(bits: u8) -> Self {
        Self(FlagBits::from_bits_retain(bits))
    }
    pub fn from_name(name: &str) -> Option<Self> {
        FlagBits::from_name(name).map(Self)
    }
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub const fn is_all(&self) -> bool {
        self.0.is_all()
    }
    pub const fn intersects(&self, other: Self) -> bool {
        self.0.intersects(other.0)
    }
    pub const fn contains(&self, other: Self) -> bool {
        self.0.contains(other.0)
    }
    pub fn insert(&mut self, other: Self) {
        self.0.insert(other.0);
    }
    pub fn remove(&mut self, other: Self) {
        self.0.remove(other.0);
    }
    pub fn toggle(&mut self, other: Self) {
        self.0.toggle(other.0);
    }
    pub fn set(&mut self, other: Self, value: bool) {
        self.0.set(other.0, value);
    }
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0.intersection(other.0))
    }
    pub const fn union(self, other: Self) -> Self {
        Self(self.0.union(other.0))
    }
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0.difference(other.0))
    }
    pub const fn symmetric_difference(self, other: Self) -> Self {
        Self(self.0.symmetric_difference(other.0))
    }
    pub const fn complement(self) -> Self {
        Self(self.0.complement())
    }
    pub const fn iter(&self) -> InvoiceFlagsIter {
        InvoiceFlagsIter(self.0.iter())
    }
    pub const fn iter_names(&self) -> InvoiceFlagNames {
        InvoiceFlagNames(self.0.iter_names())
    }
}

/// Iterator over set flags; any unknown bits are returned together at the end.
pub struct InvoiceFlagsIter(bitflags::iter::Iter<FlagBits>);
impl Iterator for InvoiceFlagsIter {
    type Item = InvoiceFlags;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(InvoiceFlags)
    }
}
impl std::iter::FusedIterator for InvoiceFlagsIter {}

/// Iterator over names and values of known set flags.
pub struct InvoiceFlagNames(bitflags::iter::IterNames<FlagBits>);
impl Iterator for InvoiceFlagNames {
    type Item = (&'static str, InvoiceFlags);
    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|(name, flags)| (name, InvoiceFlags(flags)))
    }
}
impl std::iter::FusedIterator for InvoiceFlagNames {}

impl IntoIterator for InvoiceFlags {
    type Item = Self;
    type IntoIter = InvoiceFlagsIter;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl Extend<InvoiceFlags> for InvoiceFlags {
    fn extend<T: IntoIterator<Item = Self>>(&mut self, values: T) {
        for value in values {
            self.insert(value);
        }
    }
}
impl FromIterator<InvoiceFlags> for InvoiceFlags {
    fn from_iter<T: IntoIterator<Item = Self>>(values: T) -> Self {
        let mut flags = Self::empty();
        flags.extend(values);
        flags
    }
}
impl std::ops::BitOr for InvoiceFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl std::ops::BitOrAssign for InvoiceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl std::ops::BitAnd for InvoiceFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl std::ops::BitAndAssign for InvoiceFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
impl std::ops::BitXor for InvoiceFlags {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}
impl std::ops::BitXorAssign for InvoiceFlags {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
impl std::ops::Sub for InvoiceFlags {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}
impl std::ops::SubAssign for InvoiceFlags {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}
impl std::ops::Not for InvoiceFlags {
    type Output = Self;
    fn not(self) -> Self {
        self.complement()
    }
}

impl std::fmt::Binary for InvoiceFlags {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Binary::fmt(&self.0, formatter)
    }
}

impl std::fmt::Octal for InvoiceFlags {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Octal::fmt(&self.0, formatter)
    }
}

impl std::fmt::LowerHex for InvoiceFlags {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.0, formatter)
    }
}

impl std::fmt::UpperHex for InvoiceFlags {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::UpperHex::fmt(&self.0, formatter)
    }
}
