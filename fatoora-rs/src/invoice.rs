pub mod validation;
use chrono::{DateTime, Utc};
use iso_currency::Currency;
use isocountry::{CountryCode, CountryCodeParseErr};
use std::{marker::PhantomData, rc::Rc};
use thiserror::Error;
pub type Result<T> = std::result::Result<T, InvoiceError>;

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
pub struct OtherId(String);
impl OtherId {
    pub fn new<S: Into<String>>(s: S) -> Self {
        OtherId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
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
        other_id: Option<String>,  // optional
    ) -> Result<Self> {
        let vat = VatId::parse(vat_id.into())?;
        Ok(Party {
            _marker: PhantomData,
            name,
            address,
            vat_id: Some(vat),
            other_id: other_id.map(OtherId::new),
        })
    }
}

impl Party<BuyerRole> {
    pub fn new(
        name: String,
        address: Address,
        vat_id: Option<String>,   // optional
        other_id: Option<String>, // required if vat_id is None
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
            other_id: other_id.map(OtherId::new),
        })
    }
}

#[derive(Debug)]
pub enum InvoiceSubType {
    Simplified,
    Standard,
}

#[derive(Debug)]
pub enum InvoiceType {
    Tax(InvoiceSubType),
    Prepayment(InvoiceSubType),
    CreditNote(InvoiceSubType, Rc<Invoice>, String), // original invoice and reason
    DebitNote(InvoiceSubType, Rc<Invoice>, String),  // original invoice and reason
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
    pub unit_price: f64,
    pub total_amount: f64,
    pub vat_rate: f64,
    pub vat_amount: f64,
    pub vat_category: VatCategory,
}

pub type LineItems = Vec<LineItem>;

#[derive(Debug)]
pub struct Invoice {
    pub invoice_type: InvoiceType,
    pub id: String,
    pub uuid: String,
    pub address: Address,
    pub issue_datetime: DateTime<Utc>,
    pub currency: Currency, // currently no separate tax/invoice currency
    pub previous_invoice_hash: String,
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
}
