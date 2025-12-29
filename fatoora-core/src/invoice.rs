pub mod sign;
pub mod validation;
pub mod xml;
mod builder;
pub use builder::{
    DraftInvoice, FinalizedInvoice, InvoiceBuilder, InvoiceView, SignedInvoice,
    SigningArtifacts,
};

use chrono::{DateTime, TimeZone, Utc};
use iso_currency::Currency;
use isocountry::{CountryCode, CountryCodeParseErr};
use std::{marker::PhantomData, rc::Rc};
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

#[derive(Debug, Error)]
pub enum QrCodeError {
    #[error("seller legal name is missing")]
    MissingSellerName,
    #[error("seller VAT ID is missing")]
    MissingSellerVat,
    #[error("TLV field {tag} exceeds 255 bytes (len={len})")]
    ValueTooLong { tag: u8, len: usize },
    #[error("QR code payload exceeds 700 characters once base64 encoded (len={len})")]
    EncodedTooLong { len: usize },
}

pub type QrResult<T> = std::result::Result<T, QrCodeError>;

#[derive(Debug, Clone, Copy, Default)]
pub struct QrOptions<'a> {
    /// Base64 encoded hash of the XML invoice (Tag 6).
    pub invoice_hash: Option<&'a str>,
    /// Base64 encoded ECDSA signature (Tag 7).
    pub ecdsa_signature: Option<&'a str>,
    /// Base64 encoded ECDSA public key (Tag 8).
    pub ecdsa_public_key: Option<&'a str>,
    /// Base64 encoded signature of the cryptographic stamp public key (Tag 9).
    pub public_key_signature: Option<&'a str>,
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

#[derive(Debug)]
pub enum InvoiceSubType {
    Simplified,
    Standard,
}

#[derive(Debug)]
pub enum InvoiceType {
    Tax(InvoiceSubType),
    Prepayment(InvoiceSubType),
    CreditNote(InvoiceSubType, Rc<InvoiceData>, String), // original invoice and reason
    DebitNote(InvoiceSubType, Rc<InvoiceData>, String),  // original invoice and reason
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

    pub(crate) fn timestamp_string(&self) -> String {
        self.issue_datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
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

fn dummy_seller_address() -> Address {
    Address {
        country_code: CountryCode::SAU,
        city: "الرياض | Riyadh".into(),
        street: "الامير سلطان | Prince Sultan".into(),
        additional_street: None,
        building_number: "2322".into(),
        additional_number: None,
        postal_code: "23333".into(),
        subdivision: Some("المربع | Al-Murabba".into()),
        district: None,
    }
}

// ---- Dummy Line Items ----

fn dummy_line_items() -> LineItems {
    vec![
        LineItem {
            description: "كتاب".into(),
            quantity: 33.0,
            unit_code: "PCE".into(),
            unit_price: 3.0,
            total_amount: 99.0,
            vat_rate: 15.0,
            vat_amount: 14.85,
            vat_category: VatCategory::Standard,
        },
        LineItem {
            description: "قلم".into(),
            quantity: 3.0,
            unit_code: "PCE".into(),
            unit_price: 34.0,
            total_amount: 102.0,
            vat_rate: 15.0,
            vat_amount: 15.30,
            vat_category: VatCategory::Standard,
        },
    ]
}

// ---- Dummy Invoice ----

pub fn dummy_invoice() -> SignedInvoice {
    let seller = Party::<SellerRole>::new(
        "LTD".into(),
        dummy_seller_address(),
        "399999999900003",                               // fake VAT
        Some(OtherId::with_scheme("1010010000", "CRN")), // CRN
    )
    .expect("valid seller");

    let issue_datetime = {
        let naive = chrono::NaiveDate::from_ymd_opt(2022, 8, 17)
            .unwrap()
            .and_hms_opt(17, 41, 8)
            .unwrap();
        Utc.from_utc_datetime(&naive)
    };

    let draft = InvoiceBuilder::new(
        InvoiceType::Tax(InvoiceSubType::Simplified),
        "SME00010",
        "8e6000cf-1a98-4174-b3e7-b5d5954bc10d",
        issue_datetime,
        Currency::SAR,
        "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        seller,
        dummy_line_items(),
        "10", // cash (ZATCA common)
        VatCategory::Standard,
    )
    .invoice_counter("10")
    .note(InvoiceNote {
        language: "ar".into(),
        text: "ABC".into(),
    })
    .allowance_reason("discount")
    .build();

    let finalized = draft.finalize().expect("finalize dummy invoice");
    finalized
        .sign(SigningArtifacts::default())
        .expect("sign dummy invoice")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64, Encoding};

    fn sample_invoice() -> FinalizedInvoice {
        let seller = Party::<SellerRole>::new(
            "Acme Inc".into(),
            dummy_seller_address(),
            "301121971500003",
            None,
        )
        .expect("valid seller");

        let line_item = LineItem {
            description: "Item".into(),
            quantity: 1.0,
            unit_code: "PCE".into(),
            unit_price: 100.0,
            total_amount: 100.0,
            vat_rate: 15.0,
            vat_amount: 15.0,
            vat_category: VatCategory::Standard,
        };

        let issue_datetime = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(12, 30, 0)
            .unwrap();

        InvoiceBuilder::new(
            InvoiceType::Tax(InvoiceSubType::Simplified),
            "INV-1",
            "uuid-123",
            Utc.from_utc_datetime(&issue_datetime),
            Currency::SAR,
            "",
            seller,
            vec![line_item],
            "10",
            VatCategory::Standard,
        )
        .build()
        .finalize()
        .expect("finalize sample invoice")
    }

    fn decode_tlv(bytes: &[u8]) -> Vec<(u8, String)> {
        let mut entries = Vec::new();
        let mut idx = 0;
        while idx < bytes.len() {
            let tag = bytes[idx];
            let len = bytes[idx + 1] as usize;
            let start = idx + 2;
            let end = start + len;
            let value = std::str::from_utf8(&bytes[start..end]).expect("utf8 value");
            entries.push((tag, value.to_string()));
            idx = end;
        }
        entries
    }

    #[test]
    fn qr_code_contains_all_required_tags() {
        let invoice = sample_invoice();
        let signing = SigningArtifacts {
            invoice_hash: Some("hash==".into()),
            ecdsa_signature: Some("signature==".into()),
            ecdsa_public_key: Some("public==".into()),
            public_key_signature: Some("stamp==".into()),
        };

        let qr = invoice
            .sign(signing)
            .expect("sign invoice")
            .qr_code()
            .to_string();
        assert!(qr.len() < 700);

        let raw = Base64::decode_vec(&qr).expect("base64 decode");
        let entries = decode_tlv(&raw);
        let expected = vec![
            (1, "Acme Inc".to_string()),
            (2, "301121971500003".to_string()),
            (3, "2024-01-01T12:30:00Z".to_string()),
            (4, "115.00".to_string()),
            (5, "15.00".to_string()),
            (6, "hash==".to_string()),
            (7, "signature==".to_string()),
            (8, "public==".to_string()),
            (9, "stamp==".to_string()),
        ];
        assert_eq!(entries, expected);
    }

    #[test]
    fn qr_code_errors_on_large_field() {
        let invoice = sample_invoice();
        let oversized = "a".repeat(300);
        let signing = SigningArtifacts {
            invoice_hash: Some(oversized),
            ..SigningArtifacts::default()
        };

        match invoice.sign(signing) {
            Err(QrCodeError::ValueTooLong { tag, .. }) => assert_eq!(tag, 6),
            other => panic!("expected ValueTooLong error, got {:?}", other),
        }
    }

    #[test]
    fn qr_code_errors_when_payload_too_long() {
        let invoice = sample_invoice();
        let long_value = "a".repeat(255);
        let signing = SigningArtifacts {
            invoice_hash: Some(long_value.clone()),
            ecdsa_signature: Some(long_value.clone()),
            ecdsa_public_key: Some(long_value.clone()),
            public_key_signature: Some(long_value),
        };

        match invoice.sign(signing) {
            Err(QrCodeError::EncodedTooLong { .. }) => {}
            other => panic!("expected EncodedTooLong error, got {:?}", other),
        }
    }
}
