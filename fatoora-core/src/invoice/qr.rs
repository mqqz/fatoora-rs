//! QR payload generation and encoding.
use super::xml::{
    lexical,
    nav::{self, Element},
};
use super::{InvoiceData, InvoiceTotalsData};
use base64ct::{Base64, Encoding};
use thiserror::Error;

/// Errors emitted when building or encoding QR payloads.
#[derive(Debug, Error)]
#[non_exhaustive]
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

impl QrCodeError {
    /// Shared classification used by bindings.
    pub fn kind(&self) -> crate::ErrorKind {
        match self {
            Self::MissingSellerName
            | Self::MissingSellerVat
            | Self::ValueTooLong { .. }
            | Self::EncodedTooLong { .. } => crate::ErrorKind::InvalidInput,
            Self::Xml(_) => crate::ErrorKind::Xml,
        }
    }
}

/// QR result alias.
pub type QrResult<T> = std::result::Result<T, QrCodeError>;

/// QR payload builder for ZATCA tags.
///
/// # Examples
/// ```rust,ignore
/// use fatoora_core::invoice::QrPayload;
/// use fatoora_core::invoice::{FinalizedInvoice, InvoiceTotalsData};
///
/// let invoice: FinalizedInvoice = unimplemented!();
/// let totals = InvoiceTotalsData::from_data(invoice.data());
/// let payload = QrPayload::from_invoice(invoice.data(), &totals)?;
/// let encoded = payload.encode()?;
/// # let _ = encoded;
/// use fatoora_core::invoice::QrCodeError;
/// # Ok::<(), QrCodeError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QrPayload {
    seller_name: String,
    seller_vat: String,
    timestamp: String,
    total_with_vat: String,
    total_vat: String,
    invoice_hash: Option<String>,
    signature: Option<String>,
    public_key: Option<String>,
    zatca_key_signature: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) enum QrField {
    SellerName,
    SellerVat,
    IssueDate,
    IssueTime,
    TotalWithVat,
    TotalVat,
}

impl QrField {
    pub(crate) fn normalize(self, value: &str) -> &str {
        match self {
            Self::SellerName => value,
            Self::SellerVat
            | Self::IssueDate
            | Self::IssueTime
            | Self::TotalWithVat
            | Self::TotalVat => value.trim(),
        }
    }
}

impl QrPayload {
    pub(crate) fn from_invoice(
        invoice: &InvoiceData,
        totals: &InvoiceTotalsData,
    ) -> QrResult<Self> {
        let seller_name = invoice.seller_name()?.to_string();
        let seller_vat = invoice.seller_vat()?.to_string();
        let timestamp = format!(
            "{}T{}",
            invoice.issue_date_string(),
            invoice.issue_time_string()
        );
        let total_with_vat = InvoiceData::format_amount(totals.payable_amount());
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
            zatca_key_signature: None,
        })
    }

    pub(crate) fn from_xml(xml: &str) -> QrResult<Self> {
        let doc = lexical::document(xml).map_err(|e| QrCodeError::Xml(e.to_string()))?;
        let invoice = Element::invoice(&doc);
        let seller = nav::seller_party(invoice);
        let seller_name = required_value(
            seller
                .aggregate("PartyLegalEntity")
                .basic("RegistrationName")
                .content(),
            "seller name",
            QrField::SellerName,
        )?;
        let seller_vat = required_value(
            seller
                .aggregate("PartyTaxScheme")
                .basic("CompanyID")
                .content(),
            "seller VAT",
            QrField::SellerVat,
        )?;
        let issue_date = required_value(
            invoice.basic("IssueDate").content(),
            "issue date",
            QrField::IssueDate,
        )?;
        let issue_time = required_value(
            invoice.basic("IssueTime").content(),
            "issue time",
            QrField::IssueTime,
        )?;
        let total_with_vat = required_value(
            invoice
                .aggregate("LegalMonetaryTotal")
                .basic("PayableAmount")
                .content(),
            "total with VAT",
            QrField::TotalWithVat,
        )?;
        let total_vat = required_value(
            nav::tax_totals(invoice)
                .next()
                .unwrap_or(Element(None))
                .basic("TaxAmount")
                .content(),
            "total VAT",
            QrField::TotalVat,
        )?;

        Ok(Self {
            seller_name,
            seller_vat,
            timestamp: format!("{issue_date}T{issue_time}"),
            total_with_vat,
            total_vat,
            invoice_hash: None,
            signature: None,
            public_key: None,
            zatca_key_signature: None,
        })
    }

    pub(crate) fn with_signing_parts(
        mut self,
        invoice_hash: Option<&str>,
        signature: Option<&str>,
        public_key: Option<&str>,
        zatca_key_signature: Option<&str>,
    ) -> Self {
        self.invoice_hash = invoice_hash.map(|value| value.to_string());
        self.signature = signature.map(|value| value.to_string());
        self.public_key = public_key.map(|value| value.to_string());
        self.zatca_key_signature = zatca_key_signature.map(|value| value.to_string());
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
        if let Some(stamp_sig) = self.zatca_key_signature.as_deref() {
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

fn required_value(value: Option<String>, label: &str, field: QrField) -> QrResult<String> {
    let value = value.ok_or_else(|| QrCodeError::Xml(format!("Missing {label} in invoice XML")))?;
    let value = field.normalize(&value);
    if value.trim().is_empty() {
        return Err(QrCodeError::Xml(format!("Empty {label} in invoice XML")));
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invoice::sign::SignedProperties;
    use crate::invoice::{
        Address, CountryCode, FinalizedInvoice, InvoiceBuilder, InvoiceSubType, InvoiceType,
        LineItem, Party, SellerRole, VatCategory,
    };
    use base64ct::{Base64, Encoding};

    fn sample_invoice() -> FinalizedInvoice {
        let seller = Party::<SellerRole>::new(
            "Acme Inc".into(),
            Address {
                country_code: CountryCode::parse("SAU").expect("country code"),
                city: "Riyadh".into(),
                street: "King Fahd".into(),
                additional_street: None,
                building_number: "1234".into(),
                additional_number: Some("5678".into()),
                postal_code: "12222".into(),
                district: None,
            },
            "301121971500003",
            None,
        )
        .expect("valid seller");

        let line_item = LineItem::new(
            "Item",
            crate::Decimal::from(1),
            "PCE",
            crate::Decimal::from(100),
            crate::Decimal::from(15),
            VatCategory::Standard,
        )
        .unwrap();

        let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified));
        builder = builder
            .id("INV-1")
            .uuid("uuid-123")
            .issue_datetime("2024-01-01T12:30:00Z")
            .currency("SAR")
            .previous_invoice_hash("hash")
            .invoice_counter(0)
            .seller(seller)
            .payment_means_code("10")
            .vat_category(VatCategory::Standard)
            .line_item(line_item);
        builder.build().expect("build sample invoice")
    }

    fn decode_tlv(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut entries = Vec::new();
        let mut idx = 0;
        while idx < bytes.len() {
            let tag = bytes[idx];
            let len = bytes[idx + 1] as usize;
            let start = idx + 2;
            let end = start + len;
            entries.push((tag, bytes[start..end].to_vec()));
            idx = end;
        }
        entries
    }

    #[test]
    fn qr_uses_document_vat_instead_of_rounded_line_vat() {
        let mut data = sample_invoice().data().clone();
        data.line_items = vec![
            LineItem::new(
                "tiny",
                crate::Decimal::from(1),
                "PCE",
                crate::Decimal::parse("0.03").unwrap(),
                crate::Decimal::from(15),
                VatCategory::Standard
            )
            .unwrap();
            3
        ];
        let totals = crate::invoice::InvoiceTotalsData::from_data(&data).unwrap();
        let payload = QrPayload::from_invoice(&data, &totals).unwrap();
        assert_eq!(payload.total_vat, "0.01");
        assert_eq!(payload.total_with_vat, "0.10");
    }

    #[test]
    fn qr_code_contains_all_required_tags() {
        let invoice = sample_invoice();
        let public_key_bytes = b"public-key";
        let public_key_b64 = Base64::encode_string(public_key_bytes);
        let stamp_bytes = b"stamp";
        let stamp_b64 = Base64::encode_string(stamp_bytes);
        let signing = SignedProperties::from_qr_parts(
            "hash==",
            "signature==",
            &public_key_b64,
            Some(&stamp_b64),
        );

        let signed_xml = invoice.to_xml().expect("serialize invoice");
        let qr = invoice
            .sign_with_bundle(signing, signed_xml)
            .expect("sign invoice")
            .qr_code()
            .to_string();
        assert!(qr.len() < 700);

        let raw = Base64::decode_vec(&qr).expect("base64 decode");
        let entries = decode_tlv(&raw);
        let expected = vec![
            (1, b"Acme Inc".to_vec()),
            (2, b"301121971500003".to_vec()),
            (3, b"2024-01-01T12:30:00".to_vec()),
            (4, b"115.00".to_vec()),
            (5, b"15.00".to_vec()),
            (6, b"hash==".to_vec()),
            (7, b"signature==".to_vec()),
            (8, public_key_bytes.to_vec()),
            (9, stamp_bytes.to_vec()),
        ];
        assert_eq!(entries, expected);
    }

    #[test]
    fn qr_code_errors_on_large_field() {
        let invoice = sample_invoice();
        let oversized = "a".repeat(300);
        let pk_b64 = Base64::encode_string(b"pk");
        let signing = SignedProperties::from_qr_parts(&oversized, "sig", &pk_b64, None);

        let signed_xml = invoice.to_xml().expect("serialize invoice");
        match invoice.sign_with_bundle(signing, signed_xml) {
            Err(QrCodeError::ValueTooLong { tag, .. }) => assert_eq!(tag, 6),
            other => panic!("expected ValueTooLong error, got {:?}", other),
        }
    }

    #[test]
    fn qr_code_errors_when_payload_too_long() {
        let invoice = sample_invoice();
        let long_value = "a".repeat(200);
        let long_key_bytes = vec![b'k'; 200];
        let long_key_b64 = Base64::encode_string(&long_key_bytes);
        let signing = SignedProperties::from_qr_parts(
            &long_value,
            &long_value,
            &long_key_b64,
            Some(&long_key_b64),
        );

        let signed_xml = invoice.to_xml().expect("serialize invoice");
        match invoice.sign_with_bundle(signing, signed_xml) {
            Err(QrCodeError::EncodedTooLong { .. }) => {}
            other => panic!("expected EncodedTooLong error, got {:?}", other),
        }
    }
}
