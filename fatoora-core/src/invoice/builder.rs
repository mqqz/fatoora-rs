//! Invoice builder and view types.
use super::{
    Buyer, CurrencyCode, InvoiceData, InvoiceError, InvoiceField, InvoiceFlags, InvoiceNote,
    InvoiceTimestamp, InvoiceTotalsData, InvoiceType, LineItems, QrPayload, QrResult, Seller,
    ValidationError, ValidationIssue, ValidationKind, VatCategory,
};
use crate::invoice::sign::{
    InvoiceSigner, SignedProperties, SigningError, invoice_hash_base64_from_xml,
};

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

/// Builder for creating a validated invoice.
///
/// # Examples
/// ```rust,no_run
/// use fatoora_core::invoice::{
///     InvoiceBuilder, InvoiceSubType, InvoiceType, LineItem, VatCategory, Seller,
/// };
///
/// let seller: Seller = unimplemented!();
/// let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified));
/// builder
///     .set_id("INV-1")
///     .set_uuid("uuid-1")
///     .set_issue_datetime("2024-01-01T12:30:00Z")
///     .set_currency("SAR")
///     .set_previous_invoice_hash("hash")
///     .set_invoice_counter(1)
///     .set_seller(seller)
///     .set_payment_means_code("10")
///     .set_vat_category(VatCategory::Standard)
///     .add_line_item(LineItem::new("Item", 1.0, "PCE", 100.0, 15.0, VatCategory::Standard));
///
/// let invoice = builder.build()?;
/// # let _ = invoice;
/// use fatoora_core::invoice::InvoiceError;
/// # Ok::<(), InvoiceError>(())
/// ```
#[derive(Debug, Clone)]
pub struct InvoiceBuilder {
    invoice_type: InvoiceType,
    id: Option<String>,
    uuid: Option<String>,
    issue_datetime: Option<String>,
    currency: Option<String>,
    previous_invoice_hash: Option<String>,
    invoice_counter: Option<u64>,
    note: Option<InvoiceNote>,
    seller: Option<Seller>,
    buyer: Option<Buyer>,
    line_items: LineItems,
    payment_means_code: Option<String>,
    vat_category: Option<VatCategory>,
    flags: InvoiceFlags,
    invoice_level_charge: f64,
    invoice_level_discount: f64,
    allowance_reason: Option<String>,
}

impl InvoiceBuilder {
    /// Create a builder with the invoice type.
    pub fn new(invoice_type: InvoiceType) -> Self {
        Self {
            invoice_type,
            id: None,
            uuid: None,
            issue_datetime: None,
            currency: None,
            previous_invoice_hash: None,
            invoice_counter: None,
            note: None,
            seller: None,
            buyer: None,
            line_items: Vec::new(),
            payment_means_code: None,
            vat_category: None,
            flags: InvoiceFlags::empty(),
            invoice_level_charge: 0.0,
            invoice_level_discount: 0.0,
            allowance_reason: None,
        }
    }

    pub fn set_id(&mut self, id: impl Into<String>) -> &mut Self {
        self.id = Some(id.into());
        self
    }

    pub fn set_uuid(&mut self, uuid: impl Into<String>) -> &mut Self {
        self.uuid = Some(uuid.into());
        self
    }

    pub fn set_issue_datetime(&mut self, issue_datetime: impl Into<String>) -> &mut Self {
        self.issue_datetime = Some(issue_datetime.into());
        self
    }

    pub fn set_currency(&mut self, currency: impl Into<String>) -> &mut Self {
        self.currency = Some(currency.into());
        self
    }

    pub fn set_previous_invoice_hash(&mut self, hash: impl Into<String>) -> &mut Self {
        self.previous_invoice_hash = Some(hash.into());
        self
    }

    pub fn set_invoice_counter(&mut self, counter: u64) -> &mut Self {
        self.invoice_counter = Some(counter);
        self
    }

    pub fn set_seller(&mut self, seller: Seller) -> &mut Self {
        self.seller = Some(seller);
        self
    }

    pub fn invoice_level_charge(&mut self, charge: f64) -> &mut Self {
        self.invoice_level_charge = charge;
        self
    }

    pub fn invoice_level_discount(&mut self, discount: f64) -> &mut Self {
        self.invoice_level_discount = discount;
        self
    }

    pub fn allowance_reason(&mut self, reason: impl Into<String>) -> &mut Self {
        self.allowance_reason = Some(reason.into());
        self
    }

    pub fn set_note(&mut self, note: InvoiceNote) -> &mut Self {
        self.note = Some(note);
        self
    }

    pub fn set_buyer(&mut self, buyer: Buyer) -> &mut Self {
        self.buyer = Some(buyer);
        self
    }

    pub fn set_allowance(&mut self, reason: impl Into<String>, amount: f64) -> &mut Self {
        self.invoice_level_discount = amount;
        self.allowance_reason = Some(reason.into());
        self
    }

    pub fn set_payment_means_code(&mut self, code: impl Into<String>) -> &mut Self {
        self.payment_means_code = Some(code.into());
        self
    }

    pub fn set_vat_category(&mut self, vat_category: VatCategory) -> &mut Self {
        self.vat_category = Some(vat_category);
        self
    }

    pub fn add_line_item(&mut self, line_item: super::LineItem) -> &mut Self {
        self.line_items.push(line_item);
        self
    }

    // TODO these should be in a bitflag
    pub fn flags(&mut self, flags: InvoiceFlags) -> &mut Self {
        self.flags = flags;
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

        match self.id.as_deref() {
            None => push_issue(InvoiceField::Id, ValidationKind::Missing, None),
            Some(value) if value.trim().is_empty() => {
                push_issue(InvoiceField::Id, ValidationKind::Empty, None)
            }
            _ => {}
        }
        match self.uuid.as_deref() {
            None => push_issue(InvoiceField::Uuid, ValidationKind::Missing, None),
            Some(value) if value.trim().is_empty() => {
                push_issue(InvoiceField::Uuid, ValidationKind::Empty, None)
            }
            _ => {}
        }
        let issue_datetime = match self.issue_datetime.as_deref() {
            None => {
                push_issue(InvoiceField::IssueDateTime, ValidationKind::Missing, None);
                None
            }
            Some(value) if value.trim().is_empty() => {
                push_issue(InvoiceField::IssueDateTime, ValidationKind::Empty, None);
                None
            }
            Some(value) => match InvoiceTimestamp::parse(value) {
                Ok(parsed) => Some(parsed),
                Err(_) => {
                    push_issue(InvoiceField::IssueDateTime, ValidationKind::InvalidFormat, None);
                    None
                }
            },
        };
        let currency = match self.currency.as_deref() {
            None => {
                push_issue(InvoiceField::Currency, ValidationKind::Missing, None);
                None
            }
            Some(value) if value.trim().is_empty() => {
                push_issue(InvoiceField::Currency, ValidationKind::Empty, None);
                None
            }
            Some(value) => match CurrencyCode::parse(value) {
                Ok(parsed) => Some(parsed),
                Err(_) => {
                    push_issue(InvoiceField::Currency, ValidationKind::InvalidFormat, None);
                    None
                }
            },
        };
        match self.previous_invoice_hash.as_deref() {
            None => push_issue(InvoiceField::PreviousInvoiceHash, ValidationKind::Missing, None),
            Some(value) if value.trim().is_empty() => {
                push_issue(InvoiceField::PreviousInvoiceHash, ValidationKind::Empty, None)
            }
            _ => {}
        }
        if self.invoice_counter.is_none() {
            push_issue(InvoiceField::InvoiceCounter, ValidationKind::Missing, None);
        }
        if self.seller.is_none() {
            push_issue(InvoiceField::Seller, ValidationKind::Missing, None);
        }
        match self.payment_means_code.as_deref() {
            None => push_issue(InvoiceField::PaymentMeansCode, ValidationKind::Missing, None),
            Some(value) if value.trim().is_empty() => {
                push_issue(InvoiceField::PaymentMeansCode, ValidationKind::Empty, None)
            }
            _ => {}
        }
        if self.vat_category.is_none() {
            push_issue(InvoiceField::VatCategory, ValidationKind::Missing, None);
        }
        if self.line_items.is_empty() {
            push_issue(InvoiceField::LineItems, ValidationKind::Missing, None);
        } else {
            for (idx, item) in self.line_items.iter().enumerate() {
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

        let invoice = InvoiceData {
            invoice_type: self.invoice_type,
            id: self.id.expect("validated id"),
            uuid: self.uuid.expect("validated uuid"),
            issue_datetime: issue_datetime.expect("validated issue datetime"),
            currency: currency.expect("validated currency"),
            previous_invoice_hash: self
                .previous_invoice_hash
                .expect("validated previous invoice hash"),
            invoice_counter: self.invoice_counter.expect("validated invoice counter"),
            note: self.note,
            seller: self.seller.expect("validated seller"),
            buyer: self.buyer,
            line_items: self.line_items,
            payment_means_code: self.payment_means_code.expect("validated payment means code"),
            vat_category: self.vat_category.expect("validated vat category"),
            flags: self.flags,
            invoice_level_charge: self.invoice_level_charge,
            invoice_level_discount: self.invoice_level_discount,
            allowance_reason: self.allowance_reason,
        };

        Ok(FinalizedInvoice {
            totals: InvoiceTotalsData::from_data(&invoice),
            data: invoice,
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

    /// Compute the base64 invoice hash for this finalized invoice.
    ///
    /// # Errors
    /// Returns [`SigningError`] if XML serialization, parsing, or hashing fails.
    pub fn hash_base64(&self) -> Result<String, SigningError> {
        use crate::invoice::xml::ToXml;
        let xml = self
            .to_xml()
            .map_err(|e| SigningError::SigningError(e.to_string()))?;
        invoice_hash_base64_from_xml(&xml)
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

    /// Compute the base64 invoice hash for the underlying finalized invoice.
    ///
    /// # Errors
    /// Returns [`SigningError`] if XML serialization, parsing, or hashing fails.
    pub fn hash_base64(&self) -> Result<String, SigningError> {
        self.finalized.hash_base64()
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
