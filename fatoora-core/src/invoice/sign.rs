//! XML signing and signature helpers.
use crate::invoice::QrPayload;
use crate::invoice::xml::ToXml;
use crate::invoice::{FinalizedInvoice, SignedInvoice};
use base64ct::{Base64, Encoding};
use bergshamra_c14n::{C14nMode, canonicalize_doc};
use k256::ecdsa::{Signature, SigningKey};
use k256::pkcs8::DecodePrivateKey;
use k256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use thiserror::Error;
use uppsala::{Document, NodeId, XPathEvaluator};
use x509_cert::{
    Certificate,
    der::{Decode, DecodePem, Encode},
};

use crate::invoice::xml::constants::{
    CAC_SIGNATURE_TEMPLATE, QR_REFERENCE_TEMPLATE, UBL_EXTENSIONS_TEMPLATE,
};
use crate::invoice::xml::dom;
/// Errors emitted by signing operations.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing error: {0}")]
    SigningError(String),
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

    // TODO can't think of a better name
    fn from_parts(
        doc: &Document<'_>,
        cert: &Certificate,
        key: &SigningKey,
    ) -> Result<SignedProperties, SigningError> {
        let invoice_hash_b64 = invoice_hash_base64(doc)?;
        let signature_b64 = sign_hash(key, &invoice_hash_b64)?;
        let cert_hash_b64 = certificate_hash_base64(cert)?;
        let (issuer, serial) = issuer_and_serial(cert)?;
        let signing_time = signing_time_from_doc(doc)?;
        let signed_props_xml =
            signed_properties_xml(&signing_time, &cert_hash_b64, &issuer, &serial);
        let signed_props_hash_b64 = signed_properties_hash_base64(&signed_props_xml)?;
        let public_key_b64 = public_key_base64(key);
        // let public_key_b64 = extract_signature_b64_from_cert(cert);
        let cert_signature_b64 = certificate_signature_base64(cert);

        Ok(SignedProperties {
            invoice_hash: invoice_hash_b64,
            signature: signature_b64,
            public_key: public_key_b64,
            issuer,
            serial,
            cert_hash: cert_hash_b64,
            signed_props_hash: signed_props_hash_b64,
            signing_time,
            zatca_key_signature: Some(cert_signature_b64),
        })
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
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| SigningError::SigningError(format!("Certificate parse error: {e:?}")))?;
        let private_key = SigningKey::from_pkcs8_der(private_key_der)
            .map_err(|e| SigningError::SigningError(format!("Private key parse error: {e:?}")))?;
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
        let cert = Certificate::from_pem(cert_pem.as_bytes())
            .map_err(|e| SigningError::SigningError(format!("Certificate parse error: {e:?}")))?;
        let private_key = SigningKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| SigningError::SigningError(format!("Private key parse error: {e:?}")))?;
        Ok(Self {
            csid: cert,
            private_key,
        })
    }

    pub(crate) fn sign(&self, invoice: FinalizedInvoice) -> Result<SignedInvoice, SigningError> {
        let unsigned_xml = invoice
            .to_xml()
            .map_err(|e| SigningError::SigningError(e.to_string()))?;
        let mut doc = dom::parse(&unsigned_xml)
            .map_err(|e| SigningError::SigningError(format!("XML parse error: {e}")))?;

        ensure_signature_structure(&mut doc)?;

        let signing = SignedProperties::from_parts(&doc, &self.csid, &self.private_key)?;

        let signed_invoice = invoice
            .sign_with_bundle(signing.clone(), String::new())
            .map_err(|e| SigningError::SigningError(e.to_string()))?;

        apply_signed_properties_values(&mut doc, &signing)?;
        apply_signature_values(&mut doc, &signing, &self.csid, signed_invoice.qr_code())?;

        let signed_xml = doc.to_xml();
        Ok(signed_invoice.with_xml(signed_xml))
    }

    /// Sign a pre-built invoice XML string.
    ///
    /// # Errors
    /// Returns [`SigningError`] if XML parsing or signature application fails.
    // TODO maybe return SignedInvoice instead?
    pub fn sign_xml(&self, xml: &str) -> Result<String, SigningError> {
        let mut doc = dom::parse(xml)
            .map_err(|e| SigningError::SigningError(format!("XML parse error: {e}")))?;

        ensure_signature_structure(&mut doc)?;

        let signing = SignedProperties::from_parts(&doc, &self.csid, &self.private_key)?;
        let qr_code = QrPayload::from_xml(&doc)
            .map_err(|e| SigningError::SigningError(e.to_string()))?
            .with_signing_parts(
                Some(signing.invoice_hash()),
                Some(signing.signature()),
                Some(signing.public_key()),
                signing.zatca_key_signature(),
            )
            .encode()
            .map_err(|e| SigningError::SigningError(e.to_string()))?;

        apply_signed_properties_values(&mut doc, &signing)?;
        apply_signature_values(&mut doc, &signing, &self.csid, &qr_code)?;

        Ok(doc.to_xml())
    }
    pub fn certificate(&self) -> &Certificate {
        &self.csid
    }
}

// TODO this pattern (hash -> base64) is repeated, (Use base64 func for that)
// Internal helper: compute the base64 invoice hash from a parsed XML document.
pub(crate) fn invoice_hash_base64(doc: &Document<'_>) -> Result<String, SigningError> {
    let stripped = strip_for_hashing(doc)?;
    hash_canonical(&stripped)
}

pub(crate) fn invoice_hash_base64_from_xml(xml: &str) -> Result<String, SigningError> {
    let mut doc =
        dom::parse(xml).map_err(|e| SigningError::SigningError(format!("XML parse error: {e}")))?;
    remove_hash_exclusions(&mut doc)?;
    hash_canonical(&doc)
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

fn signing_time_from_doc(doc: &Document<'_>) -> Result<String, SigningError> {
    let eval = dom::evaluator();

    if let Ok(signing_time) = xpath_text_value(
        eval,
        doc,
        "//*[local-name()='SignedProperties']//*[local-name()='SigningTime']",
        "signing time",
    ) {
        let parsed = chrono::NaiveDateTime::parse_from_str(&signing_time, "%Y-%m-%dT%H:%M:%S")
            .map_err(|e| {
                SigningError::SigningError(format!("Invalid signing time '{signing_time}': {e:?}"))
            })?;
        return Ok(parsed.format("%Y-%m-%dT%H:%M:%S").to_string());
    }

    let issue_date = xpath_text_value(eval, doc, "//cbc:IssueDate", "issue date")?;
    let issue_time = xpath_text_value(eval, doc, "//cbc:IssueTime", "issue time")?;
    let date = chrono::NaiveDate::parse_from_str(&issue_date, "%Y-%m-%d").map_err(|e| {
        SigningError::SigningError(format!("Invalid issue date '{issue_date}': {e:?}"))
    })?;
    let time = chrono::NaiveTime::parse_from_str(&issue_time, "%H:%M:%S").map_err(|e| {
        SigningError::SigningError(format!("Invalid issue time '{issue_time}': {e:?}"))
    })?;
    let naive = chrono::NaiveDateTime::new(date, time);
    Ok(naive.format("%Y-%m-%dT%H:%M:%S").to_string())
}

/// Copy `doc` with the hash-excluded subtrees removed.
///
/// `Document` is an arena of nodes borrowing the source text, so cloning it
/// copies the node table without re-lexing the XML — much cheaper than
/// serialising and reparsing just to get a tree that can be stripped.
fn strip_for_hashing<'a>(doc: &Document<'a>) -> Result<Document<'a>, SigningError> {
    let mut copy = doc.clone();
    remove_hash_exclusions(&mut copy)?;
    Ok(copy)
}

/// Base64 SHA-256 of the canonical form of an already-stripped document.
///
/// The digest is defined over the canonical octets, so the bytes are hashed
/// directly rather than being validated into a `String` first.
fn hash_canonical(doc: &Document<'_>) -> Result<String, SigningError> {
    let canonical = canonicalize_doc::<&str>(doc, C14nMode::Inclusive11, None, &[])
        .map_err(|e| SigningError::SigningError(format!("Failed to canonicalize xml: {e}")))?;
    Ok(Base64::encode_string(&Sha256::digest(&canonical)))
}

/// Canonical XML of `doc` with the hash-excluded subtrees removed.
#[cfg(test)]
fn canonicalize_invoice(doc: &Document<'_>) -> Result<String, SigningError> {
    let stripped = strip_for_hashing(doc)?;
    let canonical = canonicalize_doc::<&str>(&stripped, C14nMode::Inclusive11, None, &[])
        .map_err(|e| SigningError::SigningError(format!("Failed to canonicalize xml: {e}")))?;
    String::from_utf8(canonical)
        .map_err(|e| SigningError::SigningError(format!("Canonical XML is not UTF-8: {e}")))
}

fn remove_hash_exclusions(doc: &mut Document<'_>) -> Result<(), SigningError> {
    let eval = dom::evaluator();

    let xpaths = [
        "/*[local-name()='Invoice']//*[local-name()='UBLExtensions']",
        "//*[local-name()='AdditionalDocumentReference'][cbc:ID[normalize-space(text())='QR']]",
        "/*[local-name()='Invoice']//*[local-name()='Signature']",
    ];

    // The matches overlap: expression 3 also picks up the `ds:Signature`
    // nested inside the `ext:UBLExtensions` of expression 1. Detaching a node
    // whose ancestor is already detached only unlinks it from that orphaned
    // subtree, so collecting every match before detaching any still strips
    // exactly the same nodes from the document as one pass per expression.
    let mut excluded = Vec::new();
    for xp in xpaths {
        excluded.extend(
            dom::nodes(eval, doc, xp)
                .map_err(|e| SigningError::SigningError(format!("XPath error: {e}")))?,
        );
    }
    for node in excluded {
        doc.detach(node);
    }
    doc.prepare_xpath();
    Ok(())
}

fn xpath_text_value(
    eval: &XPathEvaluator,
    doc: &Document<'_>,
    expr: &str,
    label: &str,
) -> Result<String, SigningError> {
    match dom::text_present(eval, doc, expr)
        .map_err(|e| SigningError::SigningError(format!("XPath error for {label}: {e}")))?
    {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(SigningError::SigningError(format!(
            "Empty {label} in invoice XML"
        ))),
        None => Err(SigningError::SigningError(format!(
            "Missing {label} in invoice XML"
        ))),
    }
}

fn sign_hash(key: &SigningKey, hash_b64: &str) -> Result<String, SigningError> {
    let hash_bytes = Base64::decode_vec(hash_b64)
        .map_err(|e| SigningError::SigningError(format!("Failed to decode base64 hash: {e:?}")))?;
    let signature: Signature = key
        .sign_recoverable(&hash_bytes)
        .map_err(|e| SigningError::SigningError(format!("Failed to sign invoice hash: {e:?}")))?
        .0;
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

fn certificate_signature_base64(cert: &Certificate) -> String {
    let signature = cert.signature();

    let bytes = signature.as_bytes().unwrap();
    Base64::encode_string(bytes)
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

fn public_key_base64(key: &SigningKey) -> String {
    Base64::encode_string(
        &key.verifying_key()
            .to_public_key_der()
            .unwrap()
            .to_der()
            .unwrap(),
    )
}

fn ensure_signature_structure(doc: &mut Document<'_>) -> Result<(), SigningError> {
    let eval = dom::evaluator();
    let root = doc
        .document_element()
        .ok_or_else(|| SigningError::SigningError("missing Invoice root".into()))?;

    if nodes_at(eval, doc, "//ext:UBLExtensions")?.is_empty() {
        let ext_node = import_fragment(doc, UBL_EXTENSIONS_TEMPLATE)?;
        match first_element_child(doc, root) {
            Some(first_child) => doc.insert_before(root, ext_node, first_child),
            None => doc.append_child(root, ext_node),
        }
        check_attached(doc, ext_node, root, "UBLExtensions")?;
        doc.prepare_xpath();
    }

    if nodes_at(eval, doc, "//cac:Signature")?.is_empty() {
        let sig_node = import_fragment(doc, CAC_SIGNATURE_TEMPLATE)?;
        let references = nodes_at(eval, doc, "//cac:AdditionalDocumentReference")?;
        let parent = insert_after_last_reference(doc, sig_node, &references, root);
        check_attached(doc, sig_node, parent, "cac:Signature")?;
        doc.prepare_xpath();
    }

    Ok(())
}

/// Graft `node` after the last of `references`, falling back to the invoice root.
///
/// Returns the parent the node should have ended up under. An anchor that is
/// itself detached has no usable parent, so the root is the only sound place
/// left to put the node — `insert_after` would silently do nothing there.
fn insert_after_last_reference(
    doc: &mut Document<'_>,
    node: NodeId,
    references: &[NodeId],
    root: NodeId,
) -> NodeId {
    match references
        .last()
        .and_then(|&last| doc.parent(last).map(|parent| (last, parent)))
    {
        Some((last_ref, parent)) => {
            doc.insert_after(parent, node, last_ref);
            parent
        }
        None => {
            doc.append_child(root, node);
            root
        }
    }
}

/// Confirm an insertion actually happened.
///
/// uppsala's `insert_before` / `insert_after` / `append_child` return `()` and
/// no-op when a precondition fails, so nothing but the resulting parent link
/// distinguishes a grafted node from one still floating in the arena.
fn check_attached(
    doc: &Document<'_>,
    node: NodeId,
    parent: NodeId,
    what: &str,
) -> Result<(), SigningError> {
    if doc.parent(node) == Some(parent) {
        Ok(())
    } else {
        Err(SigningError::SigningError(format!(
            "failed to insert {what} into the invoice"
        )))
    }
}

/// Evaluate `expr` over the whole document, mapping errors into [`SigningError`].
fn nodes_at(
    eval: &XPathEvaluator,
    doc: &Document<'_>,
    expr: &str,
) -> Result<Vec<NodeId>, SigningError> {
    dom::nodes(eval, doc, expr)
        .map_err(|e| SigningError::SigningError(format!("XPath error for {expr}: {e}")))
}

fn import_fragment(doc: &mut Document<'_>, xml: &str) -> Result<NodeId, SigningError> {
    dom::import_fragment(doc, xml)
        .map_err(|e| SigningError::SigningError(format!("XML parse error: {e}")))?
        .ok_or_else(|| SigningError::SigningError("failed to import fragment".into()))
}

fn first_element_child(doc: &Document<'_>, parent: NodeId) -> Option<NodeId> {
    doc.children(parent)
        .into_iter()
        .find(|&id| doc.element(id).is_some())
}

fn apply_signed_properties_values(
    doc: &mut Document<'_>,
    signing: &SignedProperties,
) -> Result<(), SigningError> {
    // TODO this is a bit redundant
    apply_signed_properties_values_raw(
        doc,
        &signing.signing_time,
        &signing.cert_hash,
        &signing.issuer,
        &signing.serial,
    )
}

fn apply_signed_properties_values_raw(
    doc: &mut Document<'_>,
    signing_time: &str,
    cert_hash_b64: &str,
    issuer: &str,
    serial: &str,
) -> Result<(), SigningError> {
    let eval = dom::evaluator();

    set_xpath_texts(
        eval,
        doc,
        &[
            (
                "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime",
                signing_time,
            ),
            (
                "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue",
                cert_hash_b64,
            ),
            (
                "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName",
                issuer,
            ),
            (
                "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber",
                serial,
            ),
        ],
    )
}

fn apply_signature_values(
    doc: &mut Document<'_>,
    signing: &SignedProperties,
    cert: &Certificate,
    qr_code: &str,
) -> Result<(), SigningError> {
    let eval = dom::evaluator();
    let cert_b64 = Base64::encode_string(
        cert.to_der()
            .map_err(|e| {
                SigningError::SigningError(format!("Certificate DER encoding error: {e:?}"))
            })?
            .as_ref(),
    );

    set_xpath_texts(
        eval,
        doc,
        &[
            (
                "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignatureValue",
                &signing.signature,
            ),
            (
                "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
                &cert_b64,
            ),
            (
                "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue",
                &signing.signed_props_hash,
            ),
            (
                "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@Id='invoiceSignedData']/ds:DigestValue",
                &signing.invoice_hash,
            ),
        ],
    )?;

    set_qr_code(doc, qr_code)?;
    Ok(())
}

fn set_qr_code(doc: &mut Document<'_>, qr_code: &str) -> Result<(), SigningError> {
    let eval = dom::evaluator();
    let qr_path = "//cac:AdditionalDocumentReference[cbc:ID[normalize-space(text())='QR']]";

    if nodes_at(eval, doc, qr_path)?.is_empty() {
        let node = import_fragment(doc, QR_REFERENCE_TEMPLATE)?;
        let root = doc
            .document_element()
            .ok_or_else(|| SigningError::SigningError("missing Invoice root".into()))?;
        let references = nodes_at(eval, doc, "//cac:AdditionalDocumentReference")?;
        let parent = insert_after_last_reference(doc, node, &references, root);
        check_attached(doc, node, parent, "QR document reference")?;
        // Re-index so the freshly grafted reference is visible to the query below.
        doc.prepare_xpath();
    }

    // An invoice can arrive with a QR reference that carries no binary object —
    // the template above is skipped for it, so this is the only place left that
    // would notice, and a signed invoice without its QR payload is not signed.
    set_xpath_texts(
        eval,
        doc,
        &[(
            "//cac:AdditionalDocumentReference[cbc:ID[normalize-space(text())='QR']]/cac:Attachment/cbc:EmbeddedDocumentBinaryObject",
            qr_code,
        )],
    )
}

/// Set the text of every node matched by each path, erroring on an empty match.
///
/// The whole batch is resolved before anything is written so the document is
/// re-indexed once instead of once per path: `prepare_xpath` rebuilds the
/// attribute map and document order for the entire tree, which on a large
/// invoice costs far more than the edits themselves. Resolving up front is safe
/// because these paths select distinct text-only leaves and none of them match
/// on the text another entry rewrites.
fn set_xpath_texts(
    eval: &XPathEvaluator,
    doc: &mut Document<'_>,
    entries: &[(&str, &str)],
) -> Result<(), SigningError> {
    let mut targets = Vec::with_capacity(entries.len());
    for &(path, value) in entries {
        let nodes = nodes_at(eval, doc, path)?;
        if nodes.is_empty() {
            return Err(SigningError::SigningError(format!(
                "XPath target not found: {path}"
            )));
        }
        targets.push((nodes, value));
    }

    for (nodes, value) in targets {
        for node in nodes {
            dom::set_text(doc, node, value);
        }
    }
    doc.prepare_xpath();
    Ok(())
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
    fn canonicalized_invoice_removes_signature_exclusions() {
        let xml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
        let xml = std::fs::read_to_string(xml_path).expect("read sample invoice");
        let doc = dom::parse(&xml).expect("parse invoice");
        let canonicalized = canonicalize_invoice(&doc).expect("canonicalize invoice");

        assert!(!canonicalized.contains("<ext:UBLExtensions"));
        assert!(!canonicalized.contains("<cac:Signature"));
        assert!(!canonicalized.contains(">QR<"));
        assert!(!canonicalized.contains("<?xml"));
    }
    #[test]
    fn signed_properties_xml_matches_document() {
        let xml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
        let xml = std::fs::read_to_string(xml_path).expect("read sample invoice");
        let doc = dom::parse(&xml).expect("parse invoice");

        let signing_time_value = xml_text(
            &doc,
            "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime",
            "SigningTime",
        );
        let cert_hash = xml_text(
            &doc,
            "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue",
            "CertDigest",
        );
        let issuer = xml_text(
            &doc,
            "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName",
            "IssuerName",
        );
        let serial = xml_text(
            &doc,
            "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber",
            "SerialNumber",
        );

        let rebuilt = signed_properties_xml(&signing_time_value, &cert_hash, &issuer, &serial);

        assert!(rebuilt.contains("xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\""));
        assert!(rebuilt.contains("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""));
        assert!(rebuilt.contains(&format!(
            "<xades:SigningTime>{}</xades:SigningTime>",
            signing_time_value
        )));
        assert!(rebuilt.contains(&format!(
            "<ds:DigestValue xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{}</ds:DigestValue>",
            cert_hash
        )));
    }

    #[test]
    fn ensure_signature_structure_inserts_missing_nodes() {
        let mut doc = load_sample_doc();
        remove_nodes(&mut doc, "//ext:UBLExtensions");
        remove_nodes(&mut doc, "//cac:Signature");

        ensure_signature_structure(&mut doc).expect("ensure structure");

        assert!(!select_nodes(&doc, "//ext:UBLExtensions").is_empty());
        assert!(!select_nodes(&doc, "//cac:Signature").is_empty());
    }

    #[test]
    fn apply_signed_properties_values_updates_expected_nodes() {
        let mut doc = load_sample_doc();
        let signing_time = "2024-02-02T10:30:00".to_string();
        apply_signed_properties_values_raw(
            &mut doc,
            &signing_time,
            "cert_hash_b64",
            "issuer_name",
            "serial_number",
        )
        .expect("apply signed properties");

        assert_eq!(
            xml_text(&doc, "//*[local-name()='SigningTime']", "SigningTime",),
            "2024-02-02T10:30:00"
        );
        assert_eq!(
            xml_text(
                &doc,
                "//*[local-name()='CertDigest']//*[local-name()='DigestValue']",
                "CertDigest",
            ),
            "cert_hash_b64"
        );
        assert_eq!(
            xml_text(
                &doc,
                "//*[local-name()='IssuerSerial']//*[local-name()='X509IssuerName']",
                "IssuerName",
            ),
            "issuer_name"
        );
        assert_eq!(
            xml_text(
                &doc,
                "//*[local-name()='IssuerSerial']//*[local-name()='X509SerialNumber']",
                "SerialNumber",
            ),
            "serial_number"
        );
    }

    #[test]
    fn signing_time_from_doc_falls_back_to_issue_date_time() {
        let mut doc = load_sample_doc();
        remove_nodes(&mut doc, "//*[local-name()='SigningTime']");

        let issue_date = xml_text(&doc, "//cbc:IssueDate", "IssueDate");
        let issue_time = xml_text(&doc, "//cbc:IssueTime", "IssueTime");
        let date = chrono::NaiveDate::parse_from_str(&issue_date, "%Y-%m-%d").unwrap();
        let time = chrono::NaiveTime::parse_from_str(&issue_time, "%H:%M:%S").unwrap();
        let expected = chrono::NaiveDateTime::new(date, time)
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();

        let actual = signing_time_from_doc(&doc).expect("signing time");
        assert_eq!(actual, expected);
    }

    #[test]
    fn apply_signature_values_sets_signature_and_qr() {
        let mut doc = load_sample_doc();
        remove_nodes(
            &mut doc,
            "//cac:AdditionalDocumentReference[cbc:ID[normalize-space(text())='QR']]",
        );

        let signing_time = "2024-01-01T12:30:00".to_string();
        let signing = SignedProperties {
            invoice_hash: "invoice_hash_b64".to_string(),
            signature: "signature_b64".to_string(),
            public_key: "public_key_b64".to_string(),
            issuer: "issuer".to_string(),
            serial: "serial".to_string(),
            cert_hash: "cert_hash_b64".to_string(),
            signed_props_hash: "signed_props_hash_b64".to_string(),
            signing_time,
            zatca_key_signature: None,
        };

        let key = SigningKey::from_bytes((&[0x11; 32]).into()).expect("signing key");
        let cert = build_test_cert(&key);
        apply_signature_values(&mut doc, &signing, &cert, "QR_PAYLOAD").expect("apply signature");

        assert_eq!(
            xml_text(&doc, "//ds:SignatureValue", "SignatureValue"),
            "signature_b64"
        );
        assert_eq!(
            xml_text(
                &doc,
                "//ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue",
                "SignedPropertiesDigest",
            ),
            "signed_props_hash_b64"
        );
        assert_eq!(
            xml_text(
                &doc,
                "//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue",
                "InvoiceDigest",
            ),
            "invoice_hash_b64"
        );
        assert_eq!(
            xml_text(
                &doc,
                "//cac:AdditionalDocumentReference[cbc:ID[normalize-space(text())='QR']]/cac:Attachment/cbc:EmbeddedDocumentBinaryObject",
                "QR",
            ),
            "QR_PAYLOAD"
        );
    }

    #[test]
    fn set_qr_code_overwrites_existing_value() {
        let mut doc = load_sample_doc();
        set_qr_code(&mut doc, "NEW_QR").expect("set qr code");

        assert_eq!(
            xml_text(
                &doc,
                "//cac:AdditionalDocumentReference[cbc:ID[normalize-space(text())='QR']]/cac:Attachment/cbc:EmbeddedDocumentBinaryObject",
                "QR",
            ),
            "NEW_QR"
        );
    }

    #[test]
    fn set_xpath_text_rejects_missing_target() {
        let mut doc = load_sample_doc();
        let err = set_xpath_texts(
            dom::evaluator(),
            &mut doc,
            &[("//cbc:DoesNotExist", "value")],
        )
        .expect_err("missing path");
        match err {
            SigningError::SigningError(msg) => {
                assert!(msg.contains("XPath target not found"));
            }
        }
    }

    #[test]
    fn set_qr_code_rejects_reference_without_binary_object() {
        let mut doc = load_sample_doc();
        // A QR reference is present, so no template is grafted in; without the
        // binary object there is nowhere to put the payload.
        remove_nodes(
            &mut doc,
            "//cac:AdditionalDocumentReference[cbc:ID[normalize-space(text())='QR']]/cac:Attachment",
        );

        let err = set_qr_code(&mut doc, "NEW_QR").expect_err("no QR value node");
        match err {
            SigningError::SigningError(msg) => {
                assert!(msg.contains("XPath target not found"), "unexpected: {msg}");
            }
        }
    }

    #[test]
    fn xpath_text_value_distinguishes_empty_from_missing() {
        let mut doc = load_sample_doc();
        for node in select_nodes(&doc, "//cbc:IssueTime") {
            dom::set_text(&mut doc, node, "   ");
        }
        doc.prepare_xpath();

        let eval = dom::evaluator();
        let empty = xpath_text_value(eval, &doc, "//cbc:IssueTime", "issue time")
            .expect_err("blank issue time");
        match empty {
            SigningError::SigningError(msg) => {
                assert!(msg.contains("Empty issue time"), "unexpected: {msg}");
            }
        }

        let missing = xpath_text_value(eval, &doc, "//cbc:NotAnElement", "issue time")
            .expect_err("absent issue time");
        match missing {
            SigningError::SigningError(msg) => {
                assert!(msg.contains("Missing issue time"), "unexpected: {msg}");
            }
        }
    }

    #[test]
    fn invoice_hash_handles_invoices_with_many_lines() {
        // uppsala's default XPath budget is 100,000 node visits, which an
        // invoice of this size blows straight through: every `//` expression in
        // the hashing path charges one visit per node walked.
        let xml = sample_xml();
        let start = xml.find("<cac:InvoiceLine>").expect("invoice line");
        let end =
            xml.rfind("</cac:InvoiceLine>").expect("invoice line end") + "</cac:InvoiceLine>".len();
        let line = &xml[start..end];

        let mut inflated = String::with_capacity(xml.len() + line.len() * 2_000);
        inflated.push_str(&xml[..start]);
        for _ in 0..2_000 {
            inflated.push_str(line);
        }
        inflated.push_str(&xml[end..]);

        invoice_hash_base64_from_xml_str(&inflated).expect("hash a large invoice");
    }

    #[test]
    fn import_fragment_rejects_invalid_xml() {
        let mut doc = load_sample_doc();
        let err = import_fragment(&mut doc, "").expect_err("invalid fragment");
        match err {
            SigningError::SigningError(msg) => {
                assert!(
                    msg.contains("XML parse error") || msg.contains("missing fragment root"),
                    "unexpected: {msg}"
                );
            }
        }
    }

    #[test]
    fn first_element_child_skips_text_nodes() {
        let xml = "<root>\n  <child>ok</child>\n</root>";
        let doc = dom::parse(xml).expect("parse");
        let root = doc.document_element().expect("root");
        let child = first_element_child(&doc, root).expect("first element");
        assert_eq!(
            doc.element(child)
                .expect("element")
                .name
                .local_name
                .as_ref(),
            "child"
        );
    }

    #[test]
    fn xpath_returns_no_nodes_for_missing_path() {
        let doc = load_sample_doc();
        let result = dom::nodes(dom::evaluator(), &doc, "//cbc:DoesNotExist").expect("xpath");
        assert!(result.is_empty());
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
    fn public_key_base64_matches_spki_der() {
        let key = SigningKey::from_bytes((&[0x44; 32]).into()).expect("signing key");
        let expected = Base64::encode_string(
            &key.verifying_key()
                .to_public_key_der()
                .unwrap()
                .to_der()
                .unwrap(),
        );
        let actual = public_key_base64(&key);
        assert_eq!(actual, expected);
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

    /// The sample invoice text, read once and shared by every test.
    ///
    /// Documents borrow their source, so holding the text in a `static` is what
    /// lets `load_sample_doc` hand back a document with no lifetime attached.
    fn sample_xml() -> &'static str {
        static XML: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        XML.get_or_init(|| {
            let xml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
            std::fs::read_to_string(xml_path).expect("read sample invoice")
        })
    }

    fn load_sample_doc() -> Document<'static> {
        dom::parse(sample_xml()).expect("parse invoice")
    }

    fn select_nodes(doc: &Document<'_>, expr: &str) -> Vec<NodeId> {
        dom::nodes(dom::evaluator(), doc, expr).unwrap_or_else(|_| panic!("XPath error for {expr}"))
    }

    fn remove_nodes(doc: &mut Document<'_>, expr: &str) {
        for node in select_nodes(doc, expr) {
            doc.detach(node);
        }
        doc.prepare_xpath();
    }

    fn xml_text(doc: &Document<'_>, expr: &str, label: &str) -> String {
        dom::text(dom::evaluator(), doc, expr)
            .unwrap_or_else(|_| panic!("XPath error for {label}"))
            .unwrap_or_else(|| panic!("Missing {label} in invoice XML"))
    }
}
