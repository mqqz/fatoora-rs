mod builder;
mod qr;
pub mod sign;
pub mod validation;
pub mod xml;
pub use builder::{
    FinalizedInvoice, InvoiceBuilder, InvoiceView, RequiredInvoiceFields, SignedInvoice,
};
pub use qr::{QrCodeError, QrPayload, QrResult};

#[allow(unused_imports)]
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use iso_currency::Currency;
use isocountry::{CountryCode, CountryCodeParseErr};
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error;
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, InvoiceError>;

#[derive(Debug, Error)]
pub enum InvoiceError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("Invalid country code: {0}")]
    InvalidCountryCode(#[from] CountryCodeParseErr),
    #[error("Missing VAT ID for seller")]
    MissingVatForSeller,
    #[error("Missing Buyer ID for buyer")]
    MissingBuyerId,
    #[error("Invalid VAT ID format")]
    InvalidVatFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invoice validation failed")]
pub struct ValidationError {
    pub issues: Vec<ValidationIssue>,
}

impl ValidationError {
    pub fn new(issues: Vec<ValidationIssue>) -> Self {
        Self { issues }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    pub field: InvoiceField,
    pub kind: ValidationKind,
    pub line_item_index: Option<usize>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceField {
    Id,
    Uuid,
    LineItems,
    PaymentMeansCode,
    LineItemDescription,
    LineItemUnitCode,
    LineItemQuantity,
    LineItemUnitPrice,
    LineItemTotalAmount,
    LineItemVatRate,
    LineItemVatAmount,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationKind {
    Missing,
    Empty,
    InvalidFormat,
    OutOfRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    country_code: CountryCode,
    city: String,
    street: String,
    additional_street: Option<String>,
    building_number: String,
    additional_number: Option<String>,
    postal_code: String, //fix 5 digits if country is KSA
    subdivision: Option<String>,
    district: Option<String>,
}

impl Address {
    pub fn new(
        country_code: CountryCode,
        city: impl Into<String>,
        street: impl Into<String>,
        additional_street: Option<String>,
        building_number: impl Into<String>,
        additional_number: Option<String>,
        postal_code: impl Into<String>,
        subdivision: Option<String>,
        district: Option<String>,
    ) -> Self {
        Self {
            country_code,
            city: city.into(),
            street: street.into(),
            additional_street,
            building_number: building_number.into(),
            additional_number,
            postal_code: postal_code.into(),
            subdivision,
            district,
        }
    }

    pub fn country_code(&self) -> &CountryCode {
        &self.country_code
    }

    pub fn city(&self) -> &str {
        &self.city
    }

    pub fn street(&self) -> &str {
        &self.street
    }

    pub fn additional_street(&self) -> Option<&str> {
        self.additional_street.as_deref()
    }

    pub fn building_number(&self) -> &str {
        &self.building_number
    }

    pub fn additional_number(&self) -> Option<&str> {
        self.additional_number.as_deref()
    }

    pub fn postal_code(&self) -> &str {
        &self.postal_code
    }

    pub fn subdivision(&self) -> Option<&str> {
        self.subdivision.as_deref()
    }

    pub fn district(&self) -> Option<&str> {
        self.district.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VatId(String);
impl VatId {
    pub fn parse<S: Into<String>>(s: S) -> Result<Self> {
        let s = s.into().trim().to_string();
        if s.is_empty() {
            return Err(InvoiceError::InvalidVatFormat);
        }
        // TODO: tighten validation (e.g., KSA = 15 digits)
        Ok(VatId(s))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl AsRef<str> for VatId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl FromStr for VatId {
    type Err = InvoiceError;
    fn from_str(s: &str) -> Result<Self> {
        VatId::parse(s)
    }
}
impl TryFrom<String> for VatId {
    type Error = InvoiceError;
    fn try_from(value: String) -> Result<Self> {
        VatId::parse(value)
    }
}
impl TryFrom<&str> for VatId {
    type Error = InvoiceError;
    fn try_from(value: &str) -> Result<Self> {
        VatId::parse(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtherId {
    value: String,
    scheme_id: Option<String>,
}
impl OtherId {
    pub fn new<S: Into<String>>(value: S) -> Self {
        OtherId {
            value: value.into(),
            scheme_id: None,
        }
    }

    pub fn with_scheme<V: Into<String>, S: Into<String>>(value: V, scheme_id: S) -> Self {
        OtherId {
            value: value.into(),
            scheme_id: Some(scheme_id.into()),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn scheme_id(&self) -> Option<&str> {
        self.scheme_id.as_deref()
    }
}
impl AsRef<str> for OtherId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceNote {
    language: String,
    text: String,
}

impl InvoiceNote {
    pub fn new(language: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            language: language.into(),
            text: text.into(),
        }
    }

    pub fn language(&self) -> &str {
        &self.language
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

// Marker roles
pub trait PartyRole {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellerRole;
impl PartyRole for SellerRole {}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuyerRole;
impl PartyRole for BuyerRole {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Party<R: PartyRole> {
    _marker: PhantomData<R>,
    name: String,
    address: Address,
    vat_id: Option<VatId>,
    other_id: Option<OtherId>,
}

pub type Seller = Party<SellerRole>;
pub type Buyer = Party<BuyerRole>;

impl Party<SellerRole> {
    pub fn new(
        name: String,
        address: Address,
        vat_id: impl Into<String>, // required
        other_id: Option<OtherId>, // optional
    ) -> Result<Self> {
        let vat = VatId::parse(vat_id.into())?;
        Ok(Party {
            _marker: PhantomData,
            name,
            address,
            vat_id: Some(vat),
            other_id,
        })
    }
}

impl Party<BuyerRole> {
    pub fn new(
        name: String,
        address: Address,
        vat_id: Option<String>,    // optional
        other_id: Option<OtherId>, // required if vat_id is None
    ) -> Result<Self> {
        let vat = match vat_id {
            Some(v) => Some(VatId::parse(v)?),
            None => None,
        };
        if vat.is_none() && other_id.is_none() {
            return Err(InvoiceError::MissingBuyerId);
        }
        Ok(Party {
            _marker: PhantomData,
            name,
            address,
            vat_id: vat,
            other_id,
        })
    }
}

impl<R: PartyRole> Party<R> {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn vat_id(&self) -> Option<&VatId> {
        self.vat_id.as_ref()
    }

    pub fn other_id(&self) -> Option<&OtherId> {
        self.other_id.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvoiceSubType {
    Simplified,
    Standard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginalInvoiceRef {
    id: String,
    uuid: Option<String>,
    issue_date: Option<chrono::NaiveDate>,
}

impl OriginalInvoiceRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            uuid: None,
            issue_date: None,
        }
    }

    pub fn with_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuid = Some(uuid.into());
        self
    }

    pub fn with_issue_date(mut self, issue_date: chrono::NaiveDate) -> Self {
        self.issue_date = Some(issue_date);
        self
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn uuid(&self) -> Option<&str> {
        self.uuid.as_deref()
    }

    pub fn issue_date(&self) -> Option<chrono::NaiveDate> {
        self.issue_date
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvoiceType {
    Tax(InvoiceSubType),
    Prepayment(InvoiceSubType),
    CreditNote(InvoiceSubType, OriginalInvoiceRef, String), // original invoice ref + reason
    DebitNote(InvoiceSubType, OriginalInvoiceRef, String),  // original invoice ref + reason
}

impl InvoiceType {
    pub fn is_simplified(&self) -> bool {
        matches!(
            self,
            InvoiceType::Tax(InvoiceSubType::Simplified)
                | InvoiceType::Prepayment(InvoiceSubType::Simplified)
                | InvoiceType::CreditNote(InvoiceSubType::Simplified, ..)
                | InvoiceType::DebitNote(InvoiceSubType::Simplified, ..)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VatCategory {
    Exempt,
    Standard,
    Zero,
    OutOfScope,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineItem {
    description: String,
    quantity: f64,
    unit_code: String,
    unit_price: f64,
    total_amount: f64,
    vat_rate: f64,
    vat_amount: f64,
    vat_category: VatCategory,
}

impl LineItem {
    pub fn new(
        description: impl Into<String>,
        quantity: f64,
        unit_code: impl Into<String>,
        unit_price: f64,
        total_amount: f64,
        vat_rate: f64,
        vat_amount: f64,
        vat_category: VatCategory,
    ) -> Self {
        Self {
            description: description.into(),
            quantity,
            unit_code: unit_code.into(),
            unit_price,
            total_amount,
            vat_rate,
            vat_amount,
            vat_category,
        }
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn quantity(&self) -> f64 {
        self.quantity
    }

    pub fn unit_code(&self) -> &str {
        &self.unit_code
    }

    pub fn unit_price(&self) -> f64 {
        self.unit_price
    }

    pub fn total_amount(&self) -> f64 {
        self.total_amount
    }

    pub fn vat_rate(&self) -> f64 {
        self.vat_rate
    }

    pub fn vat_amount(&self) -> f64 {
        self.vat_amount
    }

    pub fn vat_category(&self) -> VatCategory {
        self.vat_category
    }
}

pub type LineItems = Vec<LineItem>;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct InvoiceFlags: u8 {
        const THIRD_PARTY = 0b00001;
        const NOMINAL = 0b00010;
        const EXPORT = 0b00100;
        const SUMMARY = 0b01000;
        const SELF_BILLED = 0b10000;
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvoiceData {
    invoice_type: InvoiceType,
    id: String,
    uuid: String,
    issue_datetime: DateTime<Utc>,
    currency: Currency, // currently no separate tax/invoice currency
    previous_invoice_hash: String,
    invoice_counter: u64,
    note: Option<InvoiceNote>,
    seller: Seller,
    buyer: Option<Buyer>,
    line_items: LineItems,
    payment_means_code: String,
    vat_category: VatCategory,

    flags: InvoiceFlags,

    invoice_level_charge: f64,
    invoice_level_discount: f64,
    allowance_reason: Option<String>,
}

impl InvoiceData {
    pub fn invoice_type(&self) -> &InvoiceType {
        &self.invoice_type
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn issue_datetime(&self) -> &DateTime<Utc> {
        &self.issue_datetime
    }

    pub fn currency(&self) -> &Currency {
        &self.currency
    }

    pub fn previous_invoice_hash(&self) -> &str {
        &self.previous_invoice_hash
    }

    pub fn invoice_counter(&self) -> u64 {
        self.invoice_counter
    }

    pub fn note(&self) -> Option<&InvoiceNote> {
        self.note.as_ref()
    }

    pub fn seller(&self) -> &Seller {
        &self.seller
    }

    pub fn buyer(&self) -> Option<&Buyer> {
        self.buyer.as_ref()
    }

    pub fn line_items(&self) -> &[LineItem] {
        &self.line_items
    }

    pub fn payment_means_code(&self) -> &str {
        &self.payment_means_code
    }

    pub fn vat_category(&self) -> VatCategory {
        self.vat_category
    }

    pub fn flags(&self) -> InvoiceFlags {
        self.flags
    }

    pub fn is_third_party(&self) -> bool {
        self.flags.contains(InvoiceFlags::THIRD_PARTY)
    }

    pub fn is_nominal(&self) -> bool {
        self.flags.contains(InvoiceFlags::NOMINAL)
    }

    pub fn is_export(&self) -> bool {
        self.flags.contains(InvoiceFlags::EXPORT)
    }

    pub fn is_summary(&self) -> bool {
        self.flags.contains(InvoiceFlags::SUMMARY)
    }

    pub fn is_self_billed(&self) -> bool {
        self.flags.contains(InvoiceFlags::SELF_BILLED)
    }

    pub fn invoice_level_charge(&self) -> f64 {
        self.invoice_level_charge
    }

    pub fn invoice_level_discount(&self) -> f64 {
        self.invoice_level_discount
    }

    pub fn allowance_reason(&self) -> Option<&str> {
        self.allowance_reason.as_deref()
    }

    pub(crate) fn seller_name(&self) -> QrResult<&str> {
        let name = self.seller.name.trim();
        if name.is_empty() {
            return Err(QrCodeError::MissingSellerName);
        }
        Ok(name)
    }

    pub(crate) fn seller_vat(&self) -> QrResult<&str> {
        let vat = self
            .seller
            .vat_id
            .as_ref()
            .ok_or(QrCodeError::MissingSellerVat)?
            .as_str()
            .trim();
        if vat.is_empty() {
            return Err(QrCodeError::MissingSellerVat);
        }
        Ok(vat)
    }

    pub(crate) fn issue_date_string(&self) -> String {
        self.issue_datetime.date_naive().to_string()
    }

    pub(crate) fn issue_time_string(&self) -> String {
        self.issue_datetime.time().format("%H:%M:%S").to_string()
    }

    pub(crate) fn format_amount(amount: f64) -> String {
        format!("{:.2}", amount)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct InvoiceTotalsData {
    line_extension: f64,
    tax_amount: f64,
    allowance_total: f64,
    charge_total: f64,
}

impl InvoiceTotalsData {
    pub(crate) fn from_data(data: &InvoiceData) -> Self {
        let line_extension: f64 = data.line_items.iter().map(|li| li.total_amount).sum();
        let tax_amount: f64 = data.line_items.iter().map(|li| li.vat_amount).sum();

        Self {
            line_extension,
            tax_amount,
            allowance_total: data.invoice_level_discount,
            charge_total: data.invoice_level_charge,
        }
    }

    pub fn line_extension(&self) -> f64 {
        self.line_extension
    }

    pub fn tax_amount(&self) -> f64 {
        self.tax_amount
    }

    pub fn allowance_total(&self) -> f64 {
        self.allowance_total
    }

    pub fn charge_total(&self) -> f64 {
        self.charge_total
    }

    pub fn taxable_amount(&self) -> f64 {
        self.line_extension - self.allowance_total + self.charge_total
    }

    pub fn tax_inclusive_amount(&self) -> f64 {
        self.taxable_amount() + self.tax_amount
    }
}
