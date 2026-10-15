//! XML signing and signature helpers.
use crate::invoice::QrPayload;
use crate::invoice::{FinalizedInvoice, SignedInvoice};
use base64ct::{Base64, Encoding};
use k256::ecdsa::{Signature, SigningKey};
#[cfg(test)]
use k256::pkcs8::EncodePublicKey;
use k256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use thiserror::Error;
use x509_cert::{
    Certificate,
    der::{Decode, DecodePem, Encode, EncodePem, pem::LineEnding},
};

/// Errors emitted by signing operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SigningError {
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("XML signing error: {0}")]
    Xml(#[source] crate::Diagnostic),
    #[error("invalid signing input: {0}")]
    InvalidInput(#[source] crate::Diagnostic),
    #[error("{0}")]
    Serialize(#[from] super::xml::InvoiceXmlError),
    #[error("{0}")]
    Invoice(#[from] super::InvoiceError),
    #[error("{0}")]
    Qr(#[from] super::QrCodeError),
}

impl SigningError {
    /// Shared classification used by bindings.
    pub fn kind(&self) -> crate::ErrorKind {
        match self {
            Self::SigningError(_) => crate::ErrorKind::Crypto,
            Self::Xml(_) => crate::ErrorKind::Xml,
            Self::InvalidInput(_) => crate::ErrorKind::InvalidInput,
            Self::Serialize(err) => err.kind(),
            Self::Invoice(err) => err.kind(),
            Self::Qr(err) => err.kind(),
        }
    }
}

/// Signed properties extracted from or applied to an invoice.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignedProperties {
    pub(crate) invoice_hash: String,
    pub(crate) signature: String,
    pub(crate) public_key: String,
    pub(crate) issuer: String,
    pub(crate) serial: String,
    pub(crate) cert_hash: String,
    pub(crate) signed_props_hash: String,
    pub(crate) signing_time: String,
    pub(crate) zatca_key_signature: Option<String>,
}

impl SignedProperties {
    pub fn invoice_hash(&self) -> &str {
        &self.invoice_hash
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn zatca_key_signature(&self) -> Option<&str> {
        self.zatca_key_signature.as_deref()
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn serial(&self) -> &str {
        &self.serial
    }

    pub fn cert_hash(&self) -> &str {
        &self.cert_hash
    }

    pub fn signed_props_hash(&self) -> &str {
        &self.signed_props_hash
    }

    pub fn signing_time(&self) -> &str {
        &self.signing_time
    }

    #[cfg(test)]
    pub(crate) fn from_qr_parts(
        invoice_hash: &str,
        signature: &str,
        public_key: &str,
        zatca_key_signature: Option<&str>,
    ) -> Self {
        Self {
            invoice_hash: invoice_hash.to_string(),
            signature: signature.to_string(),
            public_key: public_key.to_string(),
            issuer: "test".to_string(),
            serial: "test".to_string(),
            cert_hash: "test".to_string(),
            signed_props_hash: "test".to_string(),
            signing_time: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
            zatca_key_signature: zatca_key_signature.map(|s| s.to_string()),
        }
    }
}

/// Signs invoices using a certificate and private key.
///
/// # Examples
/// ```rust,no_run
/// use fatoora_core::invoice::sign::InvoiceSigner;
///
/// let cert_pem = std::fs::read_to_string("cert.pem")?;
/// let key_pem = std::fs::read_to_string("key.pem")?;
/// let signer = InvoiceSigner::from_pem(cert_pem.trim(), key_pem.trim())?;
/// # let _ = signer;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct InvoiceSigner {
    csid: Certificate,
    private_key: SigningKey,
}

impl InvoiceSigner {
    /// Construct a signer from DER-encoded certificate and key.
    ///
    /// # Errors
    /// Returns [`SigningError`] if the certificate or key cannot be parsed.
    pub fn from_der(cert_der: &[u8], private_key_der: &[u8]) -> Result<Self, SigningError> {
        let cert = Certificate::from_der(cert_der).map_err(|e| {
            SigningError::InvalidInput(crate::Diagnostic::new(format!(
                "Certificate parse error: {e:?}"
            )))
        })?;
        let private_key = SigningKey::from_pkcs8_der(private_key_der).map_err(|e| {
            SigningError::InvalidInput(crate::Diagnostic::new(format!(
                "Private key parse error: {e:?}"
            )))
        })?;
        Ok(Self {
            csid: cert,
            private_key,
        })
    }

    /// Construct a signer from PEM-encoded certificate and key.
    ///
    /// # Errors
    /// Returns [`SigningError`] if the certificate or key cannot be parsed.
    pub fn from_pem(cert_pem: &str, private_key_pem: &str) -> Result<Self, SigningError> {
        let cert = Certificate::from_pem(cert_pem.as_bytes()).map_err(|e| {
            SigningError::InvalidInput(crate::Diagnostic::new(format!(
                "Certificate parse error: {e:?}"
            )))
        })?;
        let private_key = SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
            SigningError::InvalidInput(crate::Diagnostic::new(format!(
                "Private key parse error: {e:?}"
            )))
        })?;
        Ok(Self {
            csid: cert,
            private_key,
        })
    }

    pub(crate) fn sign(&self, invoice: FinalizedInvoice) -> Result<SignedInvoice, SigningError> {
        let unsigned = invoice.to_xml()?;
        let (signing, xml) = self.sign_xml_bundle(&unsigned)?;
        invoice
            .sign_with_bundle(signing, xml)
            .map_err(SigningError::from)
    }

    /// Sign a pre-built invoice XML string and return the signed XML.
    ///
    /// Bytes outside owned signing structures are preserved. Re-signing requires
    /// the same certificate. Preserve the returned XML without reformatting it.
    ///
    /// Generates signature material without running XSD or full business-rule
    /// validation. Signing success does not establish invoice compliance.
    ///
    /// # Errors
    /// Returns [`SigningError`] if XML parsing or signature application fails.
    pub fn sign_xml(&self, xml: &str) -> Result<String, SigningError> {
        self.sign_xml_bundle(xml).map(|(_, output)| output)
    }

    fn sign_xml_bundle(&self, xml: &str) -> Result<(SignedProperties, String), SigningError> {
        use super::xml::{fragments, lexical};
        lexical::document(xml)
            .map_err(|e| SigningError::Xml(crate::Diagnostic::new(e.to_string())))?;
        let certificate = self.certificate_der()?;
        let public = self
            .csid
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|e| SigningError::SigningError(e.to_string()))?;
        let key = k256::ecdsa::VerifyingKey::from_public_key_der(&public)
            .map_err(|e| SigningError::InvalidInput(crate::Diagnostic::new(e.to_string())))?;
        if key != *self.private_key.verifying_key() {
            return Err(SigningError::InvalidInput(crate::Diagnostic::new(
                "private key does not match signing certificate",
            )));
        }
        let signing_time = fragments::signing_time(xml, &certificate)
            .map_err(|e| SigningError::InvalidInput(crate::Diagnostic::new(e)))?;
        let invoice_hash = invoice_hash_base64_from_xml(xml)?;
        let signature = sign_hash(&self.private_key, &invoice_hash)?;
        let cert_hash = certificate_hash_base64(&self.csid)?;
        let (issuer, serial) = issuer_and_serial(&self.csid)?;
        let properties = signed_properties_xml(&signing_time, &cert_hash, &issuer, &serial);
        let signing = SignedProperties {
            invoice_hash,
            signature,
            public_key: Base64::encode_string(&public),
            issuer,
            serial,
            cert_hash,
            signed_props_hash: signed_properties_hash_base64(&properties)?,
            signing_time,
            zatca_key_signature: Some(certificate_signature_base64(&self.csid)?),
        };
        let qr = QrPayload::from_xml(xml)?
            .with_signing_parts(
                Some(signing.invoice_hash()),
                Some(signing.signature()),
                Some(signing.public_key()),
                signing.zatca_key_signature(),
            )
            .encode()?;
        let fragments = fragments::render(
            &properties,
            signing.invoice_hash(),
            signing.signature(),
            &signing.signed_props_hash,
            &Base64::encode_string(&certificate),
            &qr,
        )
        .map_err(|e| SigningError::Xml(crate::Diagnostic::new(e)))?;
        let output = fragments::apply_signature_fragments(xml, &fragments)
            .map_err(|e| SigningError::InvalidInput(crate::Diagnostic::new(e)))?;
        super::validation::integrity::signing_postcondition(&output, &signing, &certificate, &qr)
            .map_err(|e| SigningError::Xml(crate::Diagnostic::new(e)))?;
        Ok((signing, output))
    }
    /// Export the certificate as DER bytes without exposing the certificate backend.
    pub fn certificate_der(&self) -> Result<Vec<u8>, SigningError> {
        self.csid
            .to_der()
            .map_err(|e| SigningError::SigningError(e.to_string()))
    }

    /// Export the certificate as PEM with LF line endings.
    pub fn certificate_pem(&self) -> Result<String, SigningError> {
        self.csid
            .to_pem(LineEnding::LF)
            .map_err(|e| SigningError::SigningError(e.to_string()))
    }
}

// Canonicalize the original source before hashing.

pub(crate) fn invoice_hash_base64_from_xml(xml: &str) -> Result<String, SigningError> {
    let canonical = super::xml::canonicalize::prepare_invoice_digest_input(xml)
        .map_err(|e| SigningError::Xml(crate::Diagnostic::new(e)))?;
    Ok(Base64::encode_string(&Sha256::digest(canonical)))
}

/// Compute the base64 invoice hash from an XML string.
///
/// # Examples
/// ```rust,no_run
/// use fatoora_core::invoice::sign::invoice_hash_base64_from_xml_str;
///
/// let xml = std::fs::read_to_string("invoice.xml")?;
/// let hash = invoice_hash_base64_from_xml_str(&xml)?;
/// # let _ = hash;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
/// Returns [`SigningError`] if parsing, canonicalization, or hashing fails.
pub fn invoice_hash_base64_from_xml_str(xml: &str) -> Result<String, SigningError> {
    invoice_hash_base64_from_xml(xml)
}

fn sign_hash(key: &SigningKey, hash_b64: &str) -> Result<String, SigningError> {
    let hash_bytes = Base64::decode_vec(hash_b64)
        .map_err(|e| SigningError::SigningError(format!("Failed to decode base64 hash: {e:?}")))?;
    let signature: Signature = key.sign_recoverable(&hash_bytes).0;
    Ok(Base64::encode_string(signature.to_der().as_bytes()))
}

fn certificate_hash_base64(cert: &Certificate) -> Result<String, SigningError> {
    let der = cert.to_der().map_err(|e| {
        SigningError::SigningError(format!("Certificate DER encoding error: {e:?}"))
    })?;
    let b64_der = Base64::encode_string(der.as_ref());
    let hash = Sha256::digest(b64_der.as_bytes());
    Ok(hex_hash_to_base64(&hash))
}

fn certificate_signature_base64(cert: &Certificate) -> Result<String, SigningError> {
    let bytes = cert.signature().as_bytes().ok_or_else(|| {
        SigningError::InvalidInput(crate::Diagnostic::new(
            "certificate signature is not byte-aligned",
        ))
    })?;
    Ok(Base64::encode_string(bytes))
}

fn issuer_and_serial(cert: &Certificate) -> Result<(String, String), SigningError> {
    let serial_bytes = cert.tbs_certificate().serial_number().as_bytes();
    let serial = serial_bytes_to_decimal_string(serial_bytes);

    let subject = cert.tbs_certificate().issuer().to_string();
    let subject = subject
        .split(',')
        .map(|part| part.trim())
        .collect::<Vec<_>>()
        .join(", ");
    Ok((subject, serial))
}

fn serial_bytes_to_decimal_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_string();
    }

    let mut digits: Vec<u8> = vec![0];
    for &byte in bytes {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            let value = (*digit as u32) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }

    while digits.len() > 1 && matches!(digits.last(), Some(0)) {
        digits.pop();
    }

    digits.iter().rev().map(|d| (b'0' + *d) as char).collect()
}

fn signed_properties_xml(
    signing_time: &str,
    cert_hash_b64: &str,
    issuer: &str,
    serial: &str,
) -> String {
    let signing_time = super::xml::fragments::text(signing_time);
    let cert_hash_b64 = super::xml::fragments::text(cert_hash_b64);
    let issuer = super::xml::fragments::text(issuer);
    let serial = super::xml::fragments::text(serial);
    format!(
        concat!(
            r#"<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">"#,
            "\n{indent:>18}<xades:SignedSignatureProperties>",
            "\n{indent:>20}<xades:SigningTime>{signing_time}</xades:SigningTime>",
            "\n{indent:>20}<xades:SigningCertificate>",
            "\n{indent:>22}<xades:Cert>",
            "\n{indent:>24}<xades:CertDigest>",
            "\n{indent:>26}<ds:DigestMethod xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
            "\n{indent:>26}<ds:DigestValue xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{digest_value}</ds:DigestValue>",
            "\n{indent:>24}</xades:CertDigest>",
            "\n{indent:>24}<xades:IssuerSerial>",
            "\n{indent:>26}<ds:X509IssuerName xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{x509_issuer_name}</ds:X509IssuerName>",
            "\n{indent:>26}<ds:X509SerialNumber xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{x509_serial_number}</ds:X509SerialNumber>",
            "\n{indent:>24}</xades:IssuerSerial>",
            "\n{indent:>22}</xades:Cert>",
            "\n{indent:>20}</xades:SigningCertificate>",
            "\n{indent:>18}</xades:SignedSignatureProperties>",
            "\n{indent:>16}</xades:SignedProperties>",
        ),
        indent = "",
        signing_time = signing_time,
        digest_value = cert_hash_b64,
        x509_issuer_name = issuer,
        x509_serial_number = serial,
    )
    .replace("\r\n", "\n")
    .to_string()
}

fn signed_properties_hash_base64(signed_props_xml: &str) -> Result<String, SigningError> {
    let hash = Sha256::digest(signed_props_xml.as_bytes());
    Ok(hex_hash_to_base64(&hash))
}

fn hex_hash_to_base64(hash: &[u8]) -> String {
    let mut hex_hash = String::with_capacity(hash.len() * 2);
    for byte in hash {
        let _ = write!(&mut hex_hash, "{:02x}", byte);
    }
    Base64::encode_string(hex_hash.as_bytes())
}

// TODO figure out how to get public key from cert properly and cross check with key
#[allow(dead_code)]
fn extract_signature_b64_from_cert(cert: &Certificate) -> Result<String, SigningError> {
    let public_key_bytes = cert
        .signature()
        .as_bytes()
        .ok_or(SigningError::SigningError(
            "Failed to extract public key from certificate".into(),
        ))?;
    Ok(Base64::encode_string(public_key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use std::str::FromStr;
    use x509_cert::{
        builder::{Builder, CertificateBuilder, profile},
        name::Name,
        serial_number::SerialNumber,
        spki::SubjectPublicKeyInfo,
        time::Validity,
    };

    #[test]
    fn serial_bytes_to_decimal_handles_large_values() {
        assert_eq!(serial_bytes_to_decimal_string(&[0x01]), "1");
        assert_eq!(serial_bytes_to_decimal_string(&[0x01, 0x00]), "256");
        assert_eq!(serial_bytes_to_decimal_string(&[0x00, 0x01]), "1");
        assert_eq!(serial_bytes_to_decimal_string(&[0xFF, 0xFF]), "65535");
    }

    #[test]
    fn certificate_hash_base64_matches_manual_digest() {
        let key = SigningKey::from_bytes((&[0x22; 32]).into()).expect("signing key");
        let cert = build_test_cert(&key);
        let cert_der = cert.to_der().expect("der");
        let b64_der = Base64::encode_string(cert_der.as_slice());
        let hash = sha2::Sha256::digest(b64_der.as_bytes());
        let mut hex_hash = String::with_capacity(hash.len() * 2);
        for byte in hash {
            use std::fmt::Write;
            let _ = write!(&mut hex_hash, "{:02x}", byte);
        }
        let expected = Base64::encode_string(hex_hash.as_bytes());
        let actual = certificate_hash_base64(&cert).expect("cert hash");
        assert_eq!(actual, expected);
    }

    #[test]
    fn issuer_and_serial_extracts_values() {
        let key = SigningKey::from_bytes((&[0x33; 32]).into()).expect("signing key");
        let cert = build_test_cert(&key);
        let (issuer, serial) = issuer_and_serial(&cert).expect("issuer serial");
        assert!(issuer.contains("CN=Test"));
        assert_eq!(serial, "1");
    }

    #[test]
    fn signed_properties_hash_base64_matches_manual_digest() {
        let signing_time = "2024-02-02T10:30:00";
        let digest_value = "digest";
        let issuer = "issuer";
        let serial = "123";
        let xml = signed_properties_xml(signing_time, digest_value, issuer, serial);
        let hash = sha2::Sha256::digest(xml.as_bytes());
        let mut hex_hash = String::with_capacity(hash.len() * 2);
        for byte in hash {
            use std::fmt::Write;
            let _ = write!(&mut hex_hash, "{:02x}", byte);
        }
        let expected = Base64::encode_string(hex_hash.as_bytes());
        let actual = signed_properties_hash_base64(&xml).expect("signed props hash");
        assert_eq!(actual, expected);
    }

    #[test]
    fn postcondition_detects_corrupt_excluded_material_for_every_invoice_type() {
        let key = SigningKey::from_bytes((&[0x55; 32]).into()).unwrap();
        let signer = InvoiceSigner {
            csid: build_test_cert(&key),
            private_key: key,
        };
        for input in [
            include_str!("../../tests/fixtures/sdk-parity/cases/simplified-invoice/input.xml"),
            include_str!("../../tests/fixtures/sdk-parity/cases/standard-invoice/input.xml"),
        ] {
            let (signing, output) = signer.sign_xml_bundle(input).unwrap();
            let doc = super::super::xml::lexical::document(&output).unwrap();
            let qr = super::super::xml::nav::document_reference(
                super::super::xml::nav::Element::invoice(&doc),
                "QR",
            )
            .aggregate("Attachment")
            .basic("EmbeddedDocumentBinaryObject")
            .content()
            .unwrap();
            let cert = signer.certificate_der().unwrap();
            for changed in [
                output.replace(signing.signature(), "AQ=="),
                output.replace(signing.cert_hash(), "AQ=="),
                output.replace(signing.signing_time(), "2000-01-01T00:00:00"),
                output.replace("URI=\"#xadesSignedProperties\"", "URI=\"#other\""),
                output.replace(&qr, "AQFB"),
            ] {
                assert_ne!(changed, output);
                assert_eq!(
                    invoice_hash_base64_from_xml(&changed).unwrap(),
                    signing.invoice_hash()
                );
                assert!(
                    super::super::validation::integrity::signing_postcondition(
                        &changed, &signing, &cert, &qr
                    )
                    .is_err()
                );
            }
        }
    }

    fn build_test_cert(key: &SigningKey) -> Certificate {
        let serial_number = SerialNumber::from(1u32);
        let validity = Validity::from_now(std::time::Duration::new(3600, 0)).expect("validity");
        let subject = Name::from_str("CN=Test,O=Fatoora,C=SA").expect("subject");
        let profile = profile::cabf::Root::new(false, subject).expect("profile");
        let public_key = key.verifying_key();
        let spki_der = public_key.to_public_key_der().expect("public key der");
        let pub_key = SubjectPublicKeyInfo::try_from(spki_der.as_bytes()).expect("spki");
        let builder =
            CertificateBuilder::new(profile, serial_number, validity, pub_key).expect("builder");
        builder
            .build::<_, k256::ecdsa::DerSignature>(key)
            .expect("certificate")
    }
}

#[cfg(test)]
mod sdk_canonical_corpus {
    use crate::invoice::xml::canonicalize;
    #[test]
    fn canonical_bytes_match_pinned_sdk() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk-parity");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
        let mut count = 0;
        for case in manifest["cases"].as_array().unwrap() {
            if case["kind"].as_str().unwrap().starts_with("csr") || case["kind"] == "malformed" {
                continue;
            }
            let id = case["id"].as_str().unwrap();
            let directory = root.join("cases").join(id);
            let xml = std::fs::read_to_string(directory.join("input.xml")).unwrap();
            let expected = std::fs::read_to_string(directory.join("canonical.xml")).unwrap();
            assert_eq!(
                String::from_utf8(canonicalize::prepare_invoice_digest_input(&xml).unwrap())
                    .unwrap(),
                expected,
                "SDK canonical bytes: {id}"
            );
            count += 1;
        }
        assert_eq!(count, 38, "required canonical cases missing");
    }
}

#[cfg(test)]
mod migration_canonical_corpus {
    use super::*;
    use crate::invoice::xml::canonicalize;

    #[test]
    fn corrected_dom_canonical_bytes_are_frozen() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/xml-migration");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
        let artifacts = manifest["artifacts"].as_object().unwrap();
        assert_eq!(artifacts.len(), 10);
        for (path, expected) in artifacts {
            let bytes = std::fs::read(root.join(path)).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&bytes)),
                expected.as_str().unwrap(),
                "{path}"
            );
            if let Some(case) = path.strip_suffix("/input.xml") {
                let xml = std::str::from_utf8(&bytes).unwrap();
                let expected =
                    std::fs::read_to_string(root.join(case).join("canonical.xml")).unwrap();
                assert_eq!(
                    String::from_utf8(canonicalize::prepare_invoice_digest_input(xml).unwrap())
                        .unwrap(),
                    expected,
                    "{case}"
                );
            }
        }
    }
}
