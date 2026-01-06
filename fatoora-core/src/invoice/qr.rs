use super::{InvoiceData, InvoiceTotalsData};
use base64ct::{Base64, Encoding};
use libxml::{tree::Document, xpath};
use thiserror::Error;

const CBC_NS: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";
const CAC_NS: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";

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
    #[error("QR XML error: {0}")]
    Xml(String),
}

pub type QrResult<T> = std::result::Result<T, QrCodeError>;

#[derive(Debug, Clone)]
pub struct QrPayload {
    seller_name: String,
    seller_vat: String,
    timestamp: String,
    total_with_vat: String,
    total_vat: String,
    invoice_hash: Option<String>,
    signature: Option<String>,
    public_key: Option<String>,
    public_key_signature: Option<String>,
}

impl QrPayload {
    pub(crate) fn from_invoice(
        invoice: &InvoiceData,
        totals: &InvoiceTotalsData,
    ) -> QrResult<Self> {
        let seller_name = invoice.seller_name()?.to_string();
        let seller_vat = invoice.seller_vat()?.to_string();
        let timestamp = invoice.timestamp_string();
        let total_with_vat = InvoiceData::format_amount(totals.tax_inclusive_amount());
        let total_vat = InvoiceData::format_amount(totals.tax_amount());

        Ok(Self {
            seller_name,
            seller_vat,
            timestamp,
            total_with_vat,
            total_vat,
            invoice_hash: None,
            signature: None,
            public_key: None,
            public_key_signature: None,
        })
    }

    pub(crate) fn from_xml(doc: &Document) -> QrResult<Self> {
        let ctx = xpath::Context::new(doc)
            .map_err(|e| QrCodeError::Xml(format!("XPath context error: {e:?}")))?;
        ctx.register_namespace("cbc", CBC_NS)
            .map_err(|e| QrCodeError::Xml(format!("XPath context error: {e:?}")))?;
        ctx.register_namespace("cac", CAC_NS)
            .map_err(|e| QrCodeError::Xml(format!("XPath context error: {e:?}")))?;

        let seller_name = xpath_text(
            &ctx,
            "//cac:AccountingSupplierParty//cac:PartyLegalEntity/cbc:RegistrationName",
            "seller name",
        )?;
        let seller_vat = xpath_text(
            &ctx,
            "//cac:AccountingSupplierParty//cac:PartyTaxScheme//cbc:CompanyID",
            "seller VAT",
        )?;
        let issue_date = xpath_text(&ctx, "//cbc:IssueDate", "issue date")?;
        let issue_time = xpath_text(&ctx, "//cbc:IssueTime", "issue time")?;
        let total_with_vat = xpath_text(
            &ctx,
            "//cac:LegalMonetaryTotal//cbc:TaxInclusiveAmount",
            "total with VAT",
        )?;
        let total_vat = xpath_text(&ctx, "//cac:TaxTotal/cbc:TaxAmount", "total VAT")?;

        Ok(Self {
            seller_name,
            seller_vat,
            timestamp: format!("{issue_date}T{issue_time}Z"),
            total_with_vat,
            total_vat,
            invoice_hash: None,
            signature: None,
            public_key: None,
            public_key_signature: None,
        })
    }

    pub(crate) fn with_signing_parts(
        mut self,
        invoice_hash: Option<&str>,
        signature: Option<&str>,
        public_key: Option<&str>,
        public_key_signature: Option<&str>,
    ) -> Self {
        self.invoice_hash = invoice_hash.map(|value| value.to_string());
        self.signature = signature.map(|value| value.to_string());
        self.public_key = public_key.map(|value| value.to_string());
        self.public_key_signature = public_key_signature.map(|value| value.to_string());
        self
    }

    pub(crate) fn encode(&self) -> QrResult<String> {
        let mut tlv = TlvBuilder::new();
        tlv.push_str(1, &self.seller_name)?;
        tlv.push_str(2, &self.seller_vat)?;
        tlv.push_str(3, &self.timestamp)?;
        tlv.push_str(4, &self.total_with_vat)?;
        tlv.push_str(5, &self.total_vat)?;

        if let Some(hash) = self.invoice_hash.as_deref() {
            tlv.push_bytes(6, hash.as_bytes())?;
        }
        if let Some(sig) = self.signature.as_deref() {
            tlv.push_bytes(7, sig.as_bytes())?;
        }
        if let Some(pk) = self.public_key.as_deref() {
            tlv.push_bytes(8, &base64ct::Base64::decode_vec(pk).unwrap())?;
        }
        if let Some(stamp_sig) = self.public_key_signature.as_deref() {
            let _ = tlv.push_bytes(
                9,
                &base64ct::Base64::decode_vec(stamp_sig).unwrap_or(vec![]),
            );
        }

        tlv.finish()
    }
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
        let mut enc_hex = String::new();
        for byte in encoded.as_bytes() {
            enc_hex.push_str(&format!("{:02X}", byte));
        }
        Ok(encoded)
    }
}

fn xpath_text(ctx: &xpath::Context, expr: &str, label: &str) -> QrResult<String> {
    let nodes = ctx
        .evaluate(expr)
        .map_err(|e| QrCodeError::Xml(format!("XPath error for {label}: {e:?}")))?
        .get_nodes_as_vec();
    let node = nodes
        .first()
        .ok_or_else(|| QrCodeError::Xml(format!("Missing {label} in invoice XML")))?;
    let value = node.get_content().trim().to_string();
    if value.is_empty() {
        return Err(QrCodeError::Xml(format!("Empty {label} in invoice XML")));
    }
    Ok(value)
}
