use crate::invoice::QrPayload;
use crate::invoice::xml::{ToXml, signed_properties_xml_string};
use crate::invoice::{FinalizedInvoice, SignedInvoice};
use base64ct::{Base64, Encoding};
use k256::ecdsa::{Signature, SigningKey};
use k256::pkcs8::DecodePrivateKey;
use k256::pkcs8::EncodePublicKey;
use libxml::{
    parser::Parser,
    tree::Node,
    tree::{Document, c14n},
    xpath,
};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use thiserror::Error;
use x509_cert::{
    Certificate,
    der::{Decode, DecodePem, Encode},
};

use crate::invoice::xml::constants::{
    CAC_NS, CAC_SIGNATURE_TEMPLATE, CBC_NS, DS_NS, EXT_NS, INVOICE_NS, QR_REFERENCE_TEMPLATE,
    SAC_NS, SBC_NS, SIG_NS, UBL_EXTENSIONS_TEMPLATE, XADES_NS,
};
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing error: {0}")]
    SigningError(String),
}

#[derive(Debug, Clone)]
pub struct SignedProperties {
    invoice_hash: String,
    signature: String,
    public_key: String,
    issuer: String,
    serial: String,
    cert_hash: String,
    signed_props_hash: String,
    signing_time: chrono::DateTime<chrono::Utc>,
    zatca_key_signature: Option<String>,
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

    pub fn signing_time(&self) -> chrono::DateTime<chrono::Utc> {
        self.signing_time
    }

    // TODO can't think of a better name
    fn from_parts(
        doc: &Document,
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

    pub(crate) fn from_parsed_parts(
        invoice_hash: String,
        signature: String,
        public_key: String,
        issuer: String,
        serial: String,
        cert_hash: String,
        signed_props_hash: String,
        signing_time: chrono::DateTime<chrono::Utc>,
        zatca_key_signature: Option<String>,
    ) -> Self {
        Self {
            invoice_hash,
            signature,
            public_key,
            issuer,
            serial,
            cert_hash,
            signed_props_hash,
            signing_time,
            zatca_key_signature,
        }
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
            signing_time: chrono::Utc::now(),
            zatca_key_signature: zatca_key_signature.map(|s| s.to_string()),
        }
    }
}

pub struct InvoiceSigner {
    csid: Certificate,
    private_key: SigningKey,
}

impl InvoiceSigner {
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
        let mut doc = Parser::default()
            .parse_string(&unsigned_xml)
            .map_err(|e| SigningError::SigningError(format!("XML parse error: {e:?}")))?;

        ensure_signature_structure(&mut doc)?;

        let signing = SignedProperties::from_parts(&doc, &self.csid, &self.private_key)?;

        let signed_invoice = invoice
            .sign_with_bundle(signing.clone(), String::new())
            .map_err(|e| SigningError::SigningError(e.to_string()))?;

        apply_signed_properties_values(&mut doc, &signing)?;
        apply_signature_values(&mut doc, &signing, &self.csid, signed_invoice.qr_code())?;

        let signed_xml = doc.to_string();
        Ok(signed_invoice.with_xml(signed_xml))
    }

    // TODO maybe return SignedInvoice instead?
    pub fn sign_xml(&self, xml: &str) -> Result<String, SigningError> {
        let mut doc = Parser::default()
            .parse_string(xml)
            .map_err(|e| SigningError::SigningError(format!("XML parse error: {e:?}")))?;

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

        Ok(doc.to_string())
    }
    pub fn certificate(&self) -> &Certificate {
        &self.csid
    }
}

// TODO this pattern (hash -> base64) is repeated, (Use base64 func for that)
pub fn invoice_hash_base64(doc: &Document) -> Result<String, SigningError> {
    let canonicalized = canonicalize_invoice(doc)?;
    // println!("Canonicalized invoice for hashing:\n{}", canonicalized);
    let hash = Sha256::digest(canonicalized.as_bytes());
    let invoice_hash_b64 = Base64::encode_string(&hash);
    Ok(invoice_hash_b64)
}

fn signing_time_from_doc(doc: &Document) -> Result<chrono::DateTime<chrono::Utc>, SigningError> {
    let ctx = xpath::Context::new(doc)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("cbc", CBC_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("xades", XADES_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;

    if let Ok(signing_time) = xpath_text_value(
        &ctx,
        "//*[local-name()='SignedProperties']//*[local-name()='SigningTime']",
        "signing time",
    ) {
        let parsed = chrono::NaiveDateTime::parse_from_str(&signing_time, "%Y-%m-%dT%H:%M:%S")
            .map_err(|e| {
                SigningError::SigningError(format!("Invalid signing time '{signing_time}': {e:?}"))
            })?;
        return Ok(chrono::DateTime::from_naive_utc_and_offset(
            parsed,
            chrono::Utc,
        ));
    }

    let issue_date = xpath_text_value(&ctx, "//cbc:IssueDate", "issue date")?;
    let issue_time = xpath_text_value(&ctx, "//cbc:IssueTime", "issue time")?;
    let date = chrono::NaiveDate::parse_from_str(&issue_date, "%Y-%m-%d").map_err(|e| {
        SigningError::SigningError(format!("Invalid issue date '{issue_date}': {e:?}"))
    })?;
    let time = chrono::NaiveTime::parse_from_str(&issue_time, "%H:%M:%S").map_err(|e| {
        SigningError::SigningError(format!("Invalid issue time '{issue_time}': {e:?}"))
    })?;
    let naive = chrono::NaiveDateTime::new(date, time);
    Ok(chrono::DateTime::from_naive_utc_and_offset(
        naive,
        chrono::Utc,
    ))
}

fn canonicalize_invoice(doc: &Document) -> Result<String, SigningError> {
    let xml = doc
        .dup()
        .map_err(|e| SigningError::SigningError(format!("Failed to duplicate xml: {e:?}")))?;
    remove_hash_exclusions(&xml)?;

    let canon_opts = c14n::CanonicalizationOptions {
        mode: c14n::CanonicalizationMode::Canonical1_1,
        inclusive_ns_prefixes: vec![],
        with_comments: false,
    };
    xml.canonicalize(canon_opts, None)
        .map_err(|e| SigningError::SigningError(format!("Failed to canonicalize xml: {e:?}")))
}

fn remove_hash_exclusions(doc: &Document) -> Result<(), SigningError> {
    let ctx = xpath::Context::new(doc)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("cbc", CBC_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;

    let xpaths = [
        "/*[local-name()='Invoice']//*[local-name()='UBLExtensions']",
        "//*[local-name()='AdditionalDocumentReference'][cbc:ID[normalize-space(text())='QR']]",
        "/*[local-name()='Invoice']//*[local-name()='Signature']",
    ];

    for xp in xpaths {
        let nodes = ctx
            .evaluate(xp)
            .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?
            .get_nodes_as_vec();
        for mut node in nodes {
            node.unlink();
        }
    }
    Ok(())
}

fn xpath_text_value(ctx: &xpath::Context, expr: &str, label: &str) -> Result<String, SigningError> {
    let nodes = ctx
        .evaluate(expr)
        .map_err(|e| SigningError::SigningError(format!("XPath error for {label}: {e:?}")))?
        .get_nodes_as_vec();
    let node = nodes
        .first()
        .ok_or_else(|| SigningError::SigningError(format!("Missing {label} in invoice XML")))?;
    let value = node.get_content().trim().to_string();
    if value.is_empty() {
        return Err(SigningError::SigningError(format!(
            "Empty {label} in invoice XML"
        )));
    }
    Ok(value)
}

fn sign_hash(key: &SigningKey, hash_b64: &str) -> Result<String, SigningError> {
    let hash_bytes = Base64::decode_vec(hash_b64)
        .map_err(|e| SigningError::SigningError(format!("Failed to decode base64 hash: {e:?}")))?;
    println!("Hash bytes to sign: {:x?}", hash_bytes);
    let signature: Signature = key
        .sign_recoverable(&hash_bytes)
        .map_err(|e| SigningError::SigningError(format!("Failed to sign invoice hash: {e:?}")))?
        .0;
    println!("Signature bytes: {:x?}", signature.to_der().as_bytes());
    Ok(Base64::encode_string(signature.to_der().as_bytes()))
    // Ok(Base64::encode_string(&signature.to_bytes()))
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
    // let mut hex_sig = String::with_capacity(bytes.len() * 2);
    // for byte in bytes {
    //     let _ = write!(&mut hex_sig, "{:02x}", byte);
    // }
    // println!("Certificate signature hex: {:?}", hex_sig);
    // println!("Bytes no enc: {:?}", bytes);
    // let enc_bytes = Base64::encode_string(bytes);
    // println!("Bytes enc: {:?}", enc_bytes);
    // println!("Bytes dec: {:?}", Base64::decode_vec(&enc_bytes).unwrap());
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
    signing_time: &chrono::DateTime<chrono::Utc>,
    cert_hash_b64: &str,
    issuer: &str,
    serial: &str,
) -> String {
    // todo remove this indirection
    signed_properties_xml_string(
        &format_signing_time(signing_time),
        cert_hash_b64,
        issuer,
        serial,
    )
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
fn extract_signature_b64_from_cert(cert: &Certificate) -> String {
    let public_key_bytes = cert.signature().as_bytes().unwrap(); // TODO handle error
    Base64::encode_string(public_key_bytes)
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

fn format_signing_time(time: &chrono::DateTime<chrono::Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S").to_string()
}

fn ensure_signature_structure(doc: &mut Document) -> Result<(), SigningError> {
    let mut root = doc
        .get_root_element()
        .ok_or_else(|| SigningError::SigningError("missing Invoice root".into()))?;
    let ctx = xpath::Context::new(doc)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    register_namespaces(&ctx)?;

    if ctx
        .evaluate("//ext:UBLExtensions")
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?
        .get_nodes_as_vec()
        .is_empty()
    {
        let mut ext_node = import_fragment(doc, UBL_EXTENSIONS_TEMPLATE)?;
        if let Some(mut first_child) = first_element_child(&root) {
            first_child
                .add_prev_sibling(&mut ext_node)
                .map_err(|e| SigningError::SigningError(e.to_string()))?;
        } else {
            root.add_child(&mut ext_node)
                .map_err(|e| SigningError::SigningError(e.to_string()))?;
        }
    }

    if ctx
        .evaluate("//cac:Signature")
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?
        .get_nodes_as_vec()
        .is_empty()
    {
        let mut sig_node = import_fragment(doc, CAC_SIGNATURE_TEMPLATE)?;
        let mut references = ctx
            .evaluate("//cac:AdditionalDocumentReference")
            .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?
            .get_nodes_as_vec();

        if let Some(mut last_ref) = references.pop() {
            last_ref
                .add_next_sibling(&mut sig_node)
                .map_err(|e| SigningError::SigningError(e.to_string()))?;
        } else {
            if let Some(mut supplier) = first_matching_node(&ctx, "//cac:AccountingSupplierParty")?
            {
                supplier
                    .add_prev_sibling(&mut sig_node)
                    .map_err(|e| SigningError::SigningError(e.to_string()))?;
            }
            root.add_child(&mut sig_node)
                .map_err(|e| SigningError::SigningError(e.to_string()))?;
        }
    }

    Ok(())
}

fn import_fragment(doc: &mut Document, xml: &str) -> Result<Node, SigningError> {
    let fragment = Parser::default()
        .parse_string(xml)
        .map_err(|e| SigningError::SigningError(format!("XML parse error: {e:?}")))?;
    let mut node = fragment
        .get_root_element()
        .ok_or_else(|| SigningError::SigningError("missing fragment root".into()))?;
    node.unlink();
    doc.import_node(&mut node)
        .map_err(|_| SigningError::SigningError("failed to import fragment".into()))
}

fn first_element_child(root: &Node) -> Option<Node> {
    let mut current = root.get_first_child();
    while let Some(node) = current {
        if node.is_element_node() {
            return Some(node);
        }
        current = node.get_next_sibling();
    }
    None
}

fn first_matching_node(ctx: &xpath::Context, path: &str) -> Result<Option<Node>, SigningError> {
    let nodes = ctx
        .evaluate(path)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?
        .get_nodes_as_vec();
    Ok(nodes.into_iter().next())
}

fn apply_signed_properties_values(
    doc: &mut Document,
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
    doc: &mut Document,
    signing_time: &chrono::DateTime<chrono::Utc>,
    cert_hash_b64: &str,
    issuer: &str,
    serial: &str,
) -> Result<(), SigningError> {
    let signing_time = format_signing_time(signing_time);
    let ctx = xpath::Context::new(doc)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    register_namespaces(&ctx)?;

    set_xpath_text(
        &ctx,
        "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime",
        &signing_time,
    )?;
    set_xpath_text(
        &ctx,
        "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue",
        cert_hash_b64,
    )?;
    set_xpath_text(
        &ctx,
        "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName",
        issuer,
    )?;
    set_xpath_text(
        &ctx,
        "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber",
        serial,
    )?;
    Ok(())
}

fn apply_signature_values(
    doc: &mut Document,
    signing: &SignedProperties,
    cert: &Certificate,
    qr_code: &str,
) -> Result<(), SigningError> {
    let ctx = xpath::Context::new(doc)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    register_namespaces(&ctx)?;

    set_xpath_text(
        &ctx,
        "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignatureValue",
        &signing.signature,
    )?;
    set_xpath_text(
        &ctx,
        "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
        &Base64::encode_string(
            cert.to_der()
                .map_err(|e| {
                    SigningError::SigningError(format!("Certificate DER encoding error: {e:?}"))
                })?
                .as_ref(),
        ),
    )?;
    set_xpath_text(
        &ctx,
        "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue",
        &signing.signed_props_hash,
    )?;
    set_xpath_text(
        &ctx,
        "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@Id='invoiceSignedData']/ds:DigestValue",
        &signing.invoice_hash,
    )?;

    set_qr_code(doc, qr_code)?;
    Ok(())
}

fn set_qr_code(doc: &mut Document, qr_code: &str) -> Result<(), SigningError> {
    let ctx = xpath::Context::new(doc)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    register_namespaces(&ctx)?;
    let qr_path = "//cac:AdditionalDocumentReference[cbc:ID[normalize-space(text())='QR']]";
    let refs = ctx
        .evaluate(qr_path)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?
        .get_nodes_as_vec();

    if refs.is_empty() {
        let mut node = import_fragment(doc, QR_REFERENCE_TEMPLATE)?;
        let mut inserted = false;
        let mut references = ctx
            .evaluate("//cac:AdditionalDocumentReference")
            .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?
            .get_nodes_as_vec();
        if let Some(mut last_ref) = references.pop() {
            last_ref
                .add_next_sibling(&mut node)
                .map_err(|e| SigningError::SigningError(e.to_string()))?;
            inserted = true;
        }
        if !inserted {
            let mut root = doc
                .get_root_element()
                .ok_or_else(|| SigningError::SigningError("missing Invoice root".into()))?;
            root.add_child(&mut node)
                .map_err(|e| SigningError::SigningError(e.to_string()))?;
        }
    }

    let value_nodes = ctx
        .evaluate("//cac:AdditionalDocumentReference[cbc:ID[normalize-space(text())='QR']]/cac:Attachment/cbc:EmbeddedDocumentBinaryObject")
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?
        .get_nodes_as_vec();
    for mut node in value_nodes {
        node.set_content(qr_code)
            .map_err(|e| SigningError::SigningError(e.to_string()))?;
    }
    Ok(())
}

fn set_xpath_text(ctx: &xpath::Context, path: &str, value: &str) -> Result<(), SigningError> {
    let nodes = ctx
        .evaluate(path)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?
        .get_nodes_as_vec();
    if nodes.is_empty() {
        return Err(SigningError::SigningError(format!(
            "XPath target not found: {path}"
        )));
    }
    for mut node in nodes {
        node.set_content(value)
            .map_err(|e| SigningError::SigningError(e.to_string()))?;
    }
    Ok(())
}

fn register_namespaces(ctx: &xpath::Context) -> Result<(), SigningError> {
    // TODO reuse context
    ctx.register_namespace("cbc", CBC_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("ubl", INVOICE_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("cac", CAC_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("ext", EXT_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("sig", SIG_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("sac", SAC_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("sbc", SBC_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("ds", DS_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    ctx.register_namespace("xades", XADES_NS)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {e:?}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let doc = Parser::default().parse_string(&xml).expect("parse invoice");
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
        let doc = Parser::default().parse_string(&xml).expect("parse invoice");
        let ctx = xpath::Context::new(&doc).expect("xpath context");
        register_namespaces(&ctx).expect("register namespaces");

        let signing_time_value = xml_text(
            &ctx,
            "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime",
            "SigningTime",
        );
        let cert_hash = xml_text(
            &ctx,
            "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue",
            "CertDigest",
        );
        let issuer = xml_text(
            &ctx,
            "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName",
            "IssuerName",
        );
        let serial = xml_text(
            &ctx,
            "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber",
            "SerialNumber",
        );

        let signing_time =
            chrono::NaiveDateTime::parse_from_str(&signing_time_value, "%Y-%m-%dT%H:%M:%S")
                .expect("parse signing time");
        let signing_time = chrono::DateTime::from_naive_utc_and_offset(signing_time, chrono::Utc);

        let rebuilt = signed_properties_xml(&signing_time, &cert_hash, &issuer, &serial);

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

    fn xml_text(ctx: &xpath::Context, expr: &str, label: &str) -> String {
        let nodes = ctx
            .evaluate(expr)
            .unwrap_or_else(|_| panic!("XPath error for {label}"))
            .get_nodes_as_vec();
        let node = nodes
            .first()
            .unwrap_or_else(|| panic!("Missing {label} in invoice XML"));
        let value = node.get_content().trim().to_string();
        if value.is_empty() {
            panic!("Empty {label} in invoice XML");
        }
        value
    }
}
