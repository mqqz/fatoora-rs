use super::{
    Buyer, InvoiceData, InvoiceError, InvoiceNote, InvoiceTotalsData, InvoiceType, LineItems,
    QrPayload, QrResult, Seller, VatCategory,
};
use crate::invoice::sign::{InvoiceSigner, SignedProperties, SigningError};
use chrono::{DateTime, Utc};
use iso_currency::Currency;

#[derive(Debug)]
pub struct FinalizedInvoice {
    data: InvoiceData,
    totals: InvoiceTotalsData,
}

// TODO maybe traits?
#[derive(Debug)]
pub struct SignedInvoice {
    finalized: FinalizedInvoice,
    signed_properties: SignedProperties,
    qr_code: String,
    signed_xml: String,
}

pub struct InvoiceBuilder {
    invoice: InvoiceData,
}

// TODO remove unneccessary constructor parameters
impl InvoiceBuilder {
    pub fn new(
        invoice_type: InvoiceType,
        id: impl Into<String>,
        uuid: impl Into<String>,
        issue_datetime: DateTime<Utc>,
        currency: Currency,
        previous_invoice_hash: impl Into<String>,
        seller: Seller,
        line_items: LineItems,
        payment_means_code: impl Into<String>,
        vat_category: VatCategory,
    ) -> Self {
        Self {
            invoice: InvoiceData {
                invoice_type,
                id: id.into(),
                uuid: uuid.into(),
                issue_datetime,
                currency,
                previous_invoice_hash: previous_invoice_hash.into(),
                invoice_counter: None,
                note: None,
                seller,
                buyer: None,
                line_items,
                payment_means_code: payment_means_code.into(),
                vat_category,
                is_third_party: false,
                is_nominal: false,
                is_export: false,
                is_summary: false,
                is_self_billed: false,
                invoice_level_charge: 0.0,
                invoice_level_discount: 0.0,
                allowance_reason: None,
            },
        }
    }

    pub fn invoice_counter(mut self, counter: impl Into<String>) -> Self {
        self.invoice.invoice_counter = Some(counter.into());
        self
    }

    pub fn note(mut self, note: InvoiceNote) -> Self {
        self.invoice.note = Some(note);
        self
    }

    pub fn buyer(mut self, buyer: Buyer) -> Self {
        self.invoice.buyer = Some(buyer);
        self
    }

    pub fn invoice_level_charge(mut self, charge: f64) -> Self {
        self.invoice.invoice_level_charge = charge;
        self
    }

    pub fn invoice_level_discount(mut self, discount: f64) -> Self {
        self.invoice.invoice_level_discount = discount;
        self
    }

    pub fn allowance_reason(mut self, reason: impl Into<String>) -> Self {
        self.invoice.allowance_reason = Some(reason.into());
        self
    }
    // todo these should be in a bitflag
    pub fn flags(
        mut self,
        is_third_party: bool,
        is_nominal: bool,
        is_export: bool,
        is_summary: bool,
        is_self_billed: bool,
    ) -> Self {
        self.invoice.is_third_party = is_third_party;
        self.invoice.is_nominal = is_nominal;
        self.invoice.is_export = is_export;
        self.invoice.is_summary = is_summary;
        self.invoice.is_self_billed = is_self_billed;
        self
    }

    pub fn build(self) -> Result<FinalizedInvoice, InvoiceError> {
        if self.invoice.line_items.is_empty() {
            return Err(InvoiceError::MissingLineItems);
        }

        Ok(FinalizedInvoice {
            totals: InvoiceTotalsData::from_data(&self.invoice),
            data: self.invoice,
        })
    }
}

impl FinalizedInvoice {
    pub fn data(&self) -> &InvoiceData {
        &self.data
    }

    pub fn totals(&self) -> &InvoiceTotalsData {
        &self.totals
    }

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
    fn data(&self) -> &InvoiceData;
    fn totals(&self) -> &InvoiceTotalsData;
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
