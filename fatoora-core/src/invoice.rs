mod builder;
mod qr;
pub mod sign;
pub mod validation;
pub mod xml;
pub use builder::{FinalizedInvoice, InvoiceBuilder, InvoiceView, SignedInvoice};
pub use qr::{QrCodeError, QrPayload, QrResult};

#[allow(unused_imports)]
use chrono::{DateTime, TimeZone, Utc};
use iso_currency::Currency;
use isocountry::{CountryCode, CountryCodeParseErr};
use std::marker::PhantomData;
use thiserror::Error;

type Result<T> = std::result::Result<T, InvoiceError>;

#[derive(Debug, Error)]
pub enum InvoiceError {
    #[error("Invalid country code: {0}")]
    InvalidCountryCode(#[from] CountryCodeParseErr),
    #[error("Missing VAT ID for seller")]
    MissingVatForSeller,
    #[error("Missing Buyer ID for buyer")]
    MissingBuyerId,
    #[error("Invalid VAT ID format")]
    InvalidVatFormat,
    #[error("Invoice must have at least one line item")]
    MissingLineItems,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub country_code: CountryCode,
    pub city: String,
    pub street: String,
    pub additional_street: Option<String>,
    pub building_number: String,
    pub additional_number: Option<String>,
    pub postal_code: String, //fix 5 digits if country is KSA
    pub subdivision: Option<String>,
    pub district: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceNote {
    pub language: String,
    pub text: String,
}

// Marker roles
pub trait PartyRole {}

#[derive(Debug)]
pub struct SellerRole;
impl PartyRole for SellerRole {}
#[derive(Debug)]
pub struct BuyerRole;
impl PartyRole for BuyerRole {}

#[derive(Debug)]
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

#[derive(Debug)]
pub enum InvoiceSubType {
    Simplified,
    Standard,
}

#[derive(Debug, Clone)]
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

#[derive(Debug)]
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

#[derive(Debug)]
pub enum VatCategory {
    Exempt,
    Standard,
    Zero,
    OutOfScope,
}
#[derive(Debug)]
pub struct LineItem {
    pub description: String,
    pub quantity: f64,
    pub unit_code: String,
    pub unit_price: f64,
    pub total_amount: f64,
    pub vat_rate: f64,
    pub vat_amount: f64,
    pub vat_category: VatCategory,
}

pub type LineItems = Vec<LineItem>;

#[derive(Debug)]
pub struct InvoiceData {
    pub invoice_type: InvoiceType,
    pub id: String,
    pub uuid: String,
    pub issue_datetime: DateTime<Utc>,
    pub currency: Currency, // currently no separate tax/invoice currency
    pub previous_invoice_hash: String,
    pub invoice_counter: Option<String>,
    pub note: Option<InvoiceNote>,
    pub seller: Seller,
    pub buyer: Option<Buyer>,
    pub line_items: LineItems,
    pub payment_means_code: String,
    pub vat_category: VatCategory,

    // these should probably be in a bitflag
    pub is_third_party: bool,
    pub is_nominal: bool,
    pub is_export: bool,
    pub is_summary: bool,
    pub is_self_billed: bool,

    pub invoice_level_charge: f64,
    pub invoice_level_discount: f64,
    pub allowance_reason: Option<String>,
}

impl InvoiceData {
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
#[derive(Debug, Clone, Copy)]
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
