use super::{
    Buyer, InvoiceData, InvoiceError, InvoiceNote, InvoiceTotalsData, InvoiceType, LineItems,
    QrPayload, QrResult, Seller, VatCategory,
};
use crate::invoice::sign::SignedProperties;
use chrono::{DateTime, Utc};
use iso_currency::Currency;

#[derive(Debug)]
pub struct DraftInvoice {
    data: InvoiceData,
}

#[derive(Debug)]
pub struct FinalizedInvoice {
    data: InvoiceData,
    totals: InvoiceTotalsData,
}

#[derive(Debug)]
pub struct SignedInvoice {
    finalized: FinalizedInvoice,
    signature_bundle: SignedProperties,
    qr_code: String,
    signed_xml: String,
}

pub struct InvoiceBuilder {
    invoice: InvoiceData,
}

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

    pub fn build(self) -> DraftInvoice {
        DraftInvoice { data: self.invoice }
    }
}

impl DraftInvoice {
    pub fn data(&self) -> &InvoiceData {
        &self.data
    }

    pub fn finalize(self) -> Result<FinalizedInvoice, InvoiceError> {
        if self.data.line_items.is_empty() {
            return Err(InvoiceError::MissingLineItems);
        }

        Ok(FinalizedInvoice {
            totals: InvoiceTotalsData::from_data(&self.data),
            data: self.data,
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

    pub fn sign(
        self,
        signature_bundle: SignedProperties,
        signed_xml: String,
    ) -> QrResult<SignedInvoice> {
        let qr_code = QrPayload::from_invoice(&self.data, &self.totals)?
            .with_signing_parts(
                Some(signature_bundle.invoice_hash()),
                Some(signature_bundle.signature()),
                Some(signature_bundle.public_key()),
                signature_bundle.public_key_signature(),
            )
            .encode()?;
        Ok(SignedInvoice {
            finalized: self,
            signature_bundle,
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

    pub fn signature_bundle(&self) -> &SignedProperties {
        &self.signature_bundle
    }

    pub fn qr_code(&self) -> &str {
        &self.qr_code
    }

    pub fn xml(&self) -> &str {
        &self.signed_xml
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
