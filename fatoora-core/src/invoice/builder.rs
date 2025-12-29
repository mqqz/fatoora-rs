use super::{
    Buyer, InvoiceData, InvoiceError, InvoiceNote, InvoiceTotalsData, InvoiceType, LineItems,
    QrCodeError, QrOptions, QrResult, Seller, VatCategory,
};
use base64ct::{Base64, Encoding};
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
    signing: SigningArtifacts,
    qr_code: String,
}

pub struct InvoiceBuilder {
    invoice: InvoiceData,
}

struct TlvBuilder {
    bytes: Vec<u8>,
}

impl TlvBuilder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn push_str(&mut self, tag: u8, value: &str) -> QrResult<()> {
        self.push_bytes(tag, value.as_bytes())
    }

    fn push_bytes(&mut self, tag: u8, value: &[u8]) -> QrResult<()> {
        if value.len() > u8::MAX as usize {
            return Err(QrCodeError::ValueTooLong {
                tag,
                len: value.len(),
            });
        }
        self.bytes.push(tag);
        self.bytes.push(value.len() as u8);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> QrResult<String> {
        let encoded = Base64::encode_string(&self.bytes);
        if encoded.len() > 700 {
            return Err(QrCodeError::EncodedTooLong { len: encoded.len() });
        }
        Ok(encoded)
    }
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

    pub fn sign(self, artifacts: SigningArtifacts) -> QrResult<SignedInvoice> {
        let qr_code = build_qr_code(&self.data, &self.totals, artifacts.as_qr_options())?;
        Ok(SignedInvoice {
            finalized: self,
            signing: artifacts,
            qr_code,
        })
    }
}

impl SigningArtifacts {
    fn as_qr_options(&self) -> QrOptions<'_> {
        QrOptions {
            invoice_hash: self.invoice_hash.as_deref(),
            ecdsa_signature: self.ecdsa_signature.as_deref(),
            ecdsa_public_key: self.ecdsa_public_key.as_deref(),
            public_key_signature: self.public_key_signature.as_deref(),
        }
    }
}

impl SignedInvoice {
    pub fn data(&self) -> &InvoiceData {
        self.finalized.data()
    }

    pub fn totals(&self) -> &InvoiceTotalsData {
        self.finalized.totals()
    }

    pub fn signing(&self) -> &SigningArtifacts {
        &self.signing
    }

    pub fn qr_code(&self) -> &str {
        &self.qr_code
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

fn build_qr_code(
    invoice: &InvoiceData,
    totals: &InvoiceTotalsData,
    options: QrOptions<'_>,
) -> QrResult<String> {
    let seller_name = invoice.seller_name()?;
    let seller_vat = invoice.seller_vat()?;

    let mut tlv = TlvBuilder::new();
    tlv.push_str(1, seller_name)?;
    tlv.push_str(2, seller_vat)?;

    tlv.push_str(3, &invoice.timestamp_string())?;
    tlv.push_str(4, &InvoiceData::format_amount(totals.tax_inclusive_amount()))?;
    tlv.push_str(5, &InvoiceData::format_amount(totals.tax_amount()))?;

    if let Some(hash) = options.invoice_hash {
        tlv.push_bytes(6, hash.as_bytes())?;
    }
    if let Some(sig) = options.ecdsa_signature {
        tlv.push_bytes(7, sig.as_bytes())?;
    }
    if let Some(pk) = options.ecdsa_public_key {
        tlv.push_bytes(8, pk.as_bytes())?;
    }
    if let Some(stamp_sig) = options.public_key_signature {
        tlv.push_bytes(9, stamp_sig.as_bytes())?;
    }

    tlv.finish()
}
#[derive(Debug, Default, Clone)]
pub struct SigningArtifacts {
    pub invoice_hash: Option<String>,
    pub ecdsa_signature: Option<String>,
    pub ecdsa_public_key: Option<String>,
    pub public_key_signature: Option<String>,
}
