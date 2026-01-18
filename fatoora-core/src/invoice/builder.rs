//! Invoice builder and view types.
use super::{
    Buyer, InvoiceData, InvoiceError, InvoiceField, InvoiceFlags, InvoiceNote, InvoiceTotalsData,
    InvoiceType, LineItems, QrPayload, QrResult, Seller, ValidationError, ValidationIssue,
    ValidationKind, VatCategory,
};
use crate::invoice::sign::{InvoiceSigner, SignedProperties, SigningError};
use chrono::{DateTime, Utc};
use iso_currency::Currency;

/// A finalized invoice with computed totals.
#[derive(Debug, Clone, PartialEq)]
pub struct FinalizedInvoice {
    data: InvoiceData,
    totals: InvoiceTotalsData,
}

// TODO maybe traits?
/// A signed invoice with QR payload and signed XML.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedInvoice {
    finalized: FinalizedInvoice,
    signed_properties: SignedProperties,
    qr_code: String,
    signed_xml: String,
}

/// Required invoice fields used to construct an [`InvoiceBuilder`].
///
/// # Examples
/// ```rust,no_run
/// use chrono::Utc;
/// use iso_currency::Currency;
/// use fatoora_core::invoice::{
///     InvoiceBuilder, RequiredInvoiceFields, InvoiceSubType, InvoiceType, LineItem,
///     LineItemFields, VatCategory, Seller,
/// };
///
/// let seller: Seller = unimplemented!();
/// let line_items = vec![LineItem::new(LineItemFields {
///     description: "Item".into(),
///     quantity: 1.0,
///     unit_code: "PCE".into(),
///     unit_price: 100.0,
///     vat_rate: 15.0,
///     vat_category: VatCategory::Standard,
/// })];
///
/// let required = RequiredInvoiceFields {
///     invoice_type: InvoiceType::Tax(InvoiceSubType::Simplified),
///     id: "INV-1".into(),
///     uuid: "uuid-1".into(),
///     issue_datetime: Utc::now(),
///     currency: Currency::SAR,
///     previous_invoice_hash: "hash".into(),
///     invoice_counter: 1,
///     seller,
///     line_items,
///     payment_means_code: "10".into(),
///     vat_category: VatCategory::Standard,
/// };
///
/// let invoice = InvoiceBuilder::new(required).build()?;
/// # let _ = invoice;
/// # Ok::<(), fatoora_core::InvoiceError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RequiredInvoiceFields {
    pub invoice_type: InvoiceType,
    pub id: String,
    pub uuid: String,
    pub issue_datetime: DateTime<Utc>,
    pub currency: Currency,
    pub previous_invoice_hash: String,
    pub invoice_counter: u64,
    pub seller: Seller,
    pub line_items: LineItems,
    pub payment_means_code: String,
    pub vat_category: VatCategory,
}

/// Builder for creating a validated invoice.
#[derive(Debug, Clone)]
pub struct InvoiceBuilder {
    invoice: InvoiceData,
}

// TODO remove unneccessary constructor parameters
impl InvoiceBuilder {
    /// Create a builder from required invoice fields.
    pub fn new(required: RequiredInvoiceFields) -> Self {
        Self::from_required(required)
    }

    pub fn from_required(required: RequiredInvoiceFields) -> Self {
        Self {
            invoice: InvoiceData {
                invoice_type: required.invoice_type,
                id: required.id,
                uuid: required.uuid,
                issue_datetime: required.issue_datetime,
                currency: required.currency,
                previous_invoice_hash: required.previous_invoice_hash,
                invoice_counter: required.invoice_counter,
                note: None,
                seller: required.seller,
                buyer: None,
                line_items: required.line_items,
                payment_means_code: required.payment_means_code,
                vat_category: required.vat_category,
                flags: InvoiceFlags::empty(),
                invoice_level_charge: 0.0,
                invoice_level_discount: 0.0,
                allowance_reason: None,
            },
        }
    }

    pub fn invoice_counter(&mut self, counter: u64) -> &mut Self {
        self.invoice.invoice_counter = counter;
        self
    }

    pub fn note(&mut self, note: InvoiceNote) -> &mut Self {
        self.invoice.note = Some(note);
        self
    }

    pub fn buyer(&mut self, buyer: Buyer) -> &mut Self {
        self.invoice.buyer = Some(buyer);
        self
    }

    pub fn invoice_level_charge(&mut self, charge: f64) -> &mut Self {
        self.invoice.invoice_level_charge = charge;
        self
    }

    pub fn invoice_level_discount(&mut self, discount: f64) -> &mut Self {
        self.invoice.invoice_level_discount = discount;
        self
    }

    pub fn allowance_reason(&mut self, reason: impl Into<String>) -> &mut Self {
        self.invoice.allowance_reason = Some(reason.into());
        self
    }

    pub fn set_note(&mut self, note: InvoiceNote) -> &mut Self {
        self.note(note)
    }

    pub fn set_buyer(&mut self, buyer: Buyer) -> &mut Self {
        self.buyer(buyer)
    }

    pub fn set_allowance(&mut self, reason: impl Into<String>, amount: f64) -> &mut Self {
        self.invoice.invoice_level_discount = amount;
        self.invoice.allowance_reason = Some(reason.into());
        self
    }

    pub fn add_line_item(&mut self, line_item: super::LineItem) -> &mut Self {
        self.invoice.line_items.push(line_item);
        self
    }

    // TODO these should be in a bitflag
    pub fn flags(&mut self, flags: InvoiceFlags) -> &mut Self {
        self.invoice.flags = flags;
        self
    }

    pub fn enable_flags(&mut self, flags: InvoiceFlags) -> &mut Self {
        self.invoice.flags.insert(flags);
        self
    }

    pub fn disable_flags(&mut self, flags: InvoiceFlags) -> &mut Self {
        self.invoice.flags.remove(flags);
        self
    }

    /// Validate the invoice and compute totals.
    ///
    /// # Errors
    /// Returns [`InvoiceError::Validation`] when required fields are missing or invalid.
    pub fn build(self) -> Result<FinalizedInvoice, InvoiceError> {
        let mut issues = Vec::new();
        let mut push_issue = |field: InvoiceField, kind: ValidationKind, line_item_index| {
            issues.push(ValidationIssue {
                field,
                kind,
                line_item_index,
            });
        };

        if self.invoice.id.trim().is_empty() {
            push_issue(InvoiceField::Id, ValidationKind::Empty, None);
        }
        if self.invoice.uuid.trim().is_empty() {
            push_issue(InvoiceField::Uuid, ValidationKind::Empty, None);
        }
        if self.invoice.payment_means_code.trim().is_empty() {
            push_issue(InvoiceField::PaymentMeansCode, ValidationKind::Empty, None);
        }
        if self.invoice.line_items.is_empty() {
            push_issue(InvoiceField::LineItems, ValidationKind::Missing, None);
        } else {
            for (idx, item) in self.invoice.line_items.iter().enumerate() {
                if item.description().trim().is_empty() {
                    push_issue(
                        InvoiceField::LineItemDescription,
                        ValidationKind::Empty,
                        Some(idx),
                    );
                }
                if item.unit_code().trim().is_empty() {
                    push_issue(
                        InvoiceField::LineItemUnitCode,
                        ValidationKind::Empty,
                        Some(idx),
                    );
                }
                if item.quantity() < 0.0 {
                    push_issue(
                        InvoiceField::LineItemQuantity,
                        ValidationKind::OutOfRange,
                        Some(idx),
                    );
                }
                if item.unit_price() < 0.0 {
                    push_issue(
                        InvoiceField::LineItemUnitPrice,
                        ValidationKind::OutOfRange,
                        Some(idx),
                    );
                }
                if item.total_amount() < 0.0 {
                    push_issue(
                        InvoiceField::LineItemTotalAmount,
                        ValidationKind::OutOfRange,
                        Some(idx),
                    );
                }
                if item.vat_rate() < 0.0 {
                    push_issue(
                        InvoiceField::LineItemVatRate,
                        ValidationKind::OutOfRange,
                        Some(idx),
                    );
                }
                if item.vat_amount() < 0.0 {
                    push_issue(
                        InvoiceField::LineItemVatAmount,
                        ValidationKind::OutOfRange,
                        Some(idx),
                    );
                }
            }
        }
        if !issues.is_empty() {
            return Err(InvoiceError::Validation(ValidationError::new(issues)));
        }

        Ok(FinalizedInvoice {
            totals: InvoiceTotalsData::from_data(&self.invoice),
            data: self.invoice,
        })
    }
}

impl FinalizedInvoice {
    /// Access the underlying invoice data.
    pub fn data(&self) -> &InvoiceData {
        &self.data
    }

    pub fn totals(&self) -> &InvoiceTotalsData {
        &self.totals
    }

    /// Sign the invoice with the provided signer.
    ///
    /// # Errors
    /// Returns [`SigningError`] if signing or XML generation fails.
    pub fn sign(self, signer: &InvoiceSigner) -> Result<SignedInvoice, SigningError> {
        signer.sign(self)
    }

    pub(crate) fn sign_with_bundle(
        self,
        signed_properties: SignedProperties,
        signed_xml: String,
    ) -> QrResult<SignedInvoice> {
        let qr_code = QrPayload::from_invoice(&self.data, &self.totals)?
            .with_signing_parts(
                Some(signed_properties.invoice_hash()),
                Some(signed_properties.signature()),
                Some(signed_properties.public_key()),
                signed_properties.zatca_key_signature(),
            )
            .encode()?;
        Ok(SignedInvoice {
            finalized: self,
            signed_properties,
            qr_code,
            signed_xml,
        })
    }
}

impl SignedInvoice {
    /// Access the underlying invoice data.
    pub fn data(&self) -> &InvoiceData {
        self.finalized.data()
    }

    pub fn totals(&self) -> &InvoiceTotalsData {
        self.finalized.totals()
    }

    pub fn signed_properties(&self) -> &SignedProperties {
        &self.signed_properties
    }

    pub fn qr_code(&self) -> &str {
        &self.qr_code
    }

    pub fn xml(&self) -> &str {
        &self.signed_xml
    }

    pub fn uuid(&self) -> &str {
        self.finalized.data().uuid.as_str()
    }

    pub fn invoice_hash(&self) -> &str {
        self.signed_properties.invoice_hash()
    }

    pub fn signature(&self) -> &str {
        self.signed_properties.signature()
    }

    pub fn public_key(&self) -> &str {
        self.signed_properties.public_key()
    }

    pub fn zatca_key_signature(&self) -> Option<&str> {
        self.signed_properties.zatca_key_signature()
    }

    pub fn to_xml_base64(&self) -> String {
        use base64ct::{Base64, Encoding};
        Base64::encode_string(self.signed_xml.as_bytes())
    }

    pub(crate) fn with_xml(mut self, signed_xml: String) -> Self {
        self.signed_xml = signed_xml;
        self
    }
}

pub trait InvoiceView {
    /// Invoice data.
    fn data(&self) -> &InvoiceData;
    /// Computed totals.
    fn totals(&self) -> &InvoiceTotalsData;
    /// Optional QR payload.
    fn qr_code(&self) -> Option<&str>;
}

impl InvoiceView for FinalizedInvoice {
    fn data(&self) -> &InvoiceData {
        self.data()
    }

    fn totals(&self) -> &InvoiceTotalsData {
        self.totals()
    }

    fn qr_code(&self) -> Option<&str> {
        None
    }
}

impl InvoiceView for SignedInvoice {
    fn data(&self) -> &InvoiceData {
        self.data()
    }

    fn totals(&self) -> &InvoiceTotalsData {
        self.totals()
    }

    fn qr_code(&self) -> Option<&str> {
        Some(self.qr_code())
    }
}
