//! Local integrity checks for the pinned SDK profile, without issuer trust claims.
use super::{
    Severity, ValidationFinding, ValidationLayer, ZatcaFinding, ZatcaStage, ZatcaStageStatus,
    ZatcaValidationReport, integrity_xml,
};
use crate::invoice::xml::{
    lexical,
    nav::{self, Nodes},
};
use base64ct::{Base64, Encoding};
use k256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use roxmltree::{Document, Node};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};
const UBL: &str = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2";
const CBC: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";
const CAC: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";
const EXT: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const C14N: &str = "http://www.w3.org/2006/12/xml-c14n11";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
#[derive(Debug)]
enum CheckError {
    Violation(&'static str, String),
    Backend(String),
}
type Checked<T> = Result<T, CheckError>;
fn bad(code: &'static str, message: impl Into<String>) -> CheckError {
    CheckError::Violation(code, message.into())
}
struct Xml<'input> {
    doc: Document<'input>,
}
impl<'input> Xml<'input> {
    fn parse(xml: &'input str) -> Result<Self, String> {
        lexical::document(xml)
            .map(|doc| Self { doc })
            .map_err(|e| e.to_string())
    }
    fn root(&self) -> Nodes<'_, 'input> {
        let root = self.doc.root_element();
        Nodes(
            nav::is(root, UBL, "Invoice")
                .then_some(root)
                .into_iter()
                .collect(),
        )
    }
    fn signature(&self) -> Nodes<'_, 'input> {
        self.root()
            .children(EXT, "UBLExtensions")
            .children(EXT, "UBLExtension")
            .children(EXT, "ExtensionContent")
            .children(
                crate::invoice::xml::constants::SIG_NS,
                "UBLDocumentSignatures",
            )
            .children(
                crate::invoice::xml::constants::SAC_NS,
                "SignatureInformation",
            )
            .children(DS, "Signature")
    }
    fn document_reference(&self, id: &str) -> Nodes<'_, 'input> {
        self.root()
            .children(CAC, "AdditionalDocumentReference")
            .filter(|node| {
                node.children()
                    .any(|child| nav::is(child, CBC, "ID") && nav::content(child) == id)
            })
            .children(CAC, "Attachment")
            .children(CBC, "EmbeddedDocumentBinaryObject")
    }
    fn all(&self, ns: &str, local: &str) -> Nodes<'_, 'input> {
        Nodes(
            self.doc
                .descendants()
                .filter(|node| nav::is(*node, ns, local))
                .collect(),
        )
    }
    fn one<'a>(&self, nodes: &Nodes<'a, 'input>) -> Checked<Node<'a, 'input>> {
        match nodes.0.as_slice() {
            [node] => Ok(*node),
            nodes => Err(bad(
                "INTEGRITY_STRUCTURE",
                format!("Expected exactly one XML value; found {}", nodes.len()),
            )),
        }
    }
    fn text(&self, nodes: &Nodes<'_, 'input>) -> Checked<String> {
        let node = self.one(nodes)?;
        if node.children().any(|node| node.is_element()) {
            return Err(bad("INTEGRITY_STRUCTURE", "Expected a scalar XML value"));
        }
        Ok(nav::content(node))
    }
    fn attribute(&self, nodes: &Nodes<'_, 'input>, name: &str) -> Checked<String> {
        self.one(nodes)?
            .attribute(name)
            .map(str::to_owned)
            .ok_or_else(|| bad("INTEGRITY_STRUCTURE", format!("Missing {name} attribute")))
    }
    fn expect(&self, nodes: &Nodes<'_, 'input>, value: &str) -> Checked<()> {
        if self.text(nodes)? != value {
            return Err(bad("SIGNATURE_ALGORITHM", "Unsupported signature metadata"));
        }
        Ok(())
    }
    fn expect_attribute(&self, nodes: &Nodes<'_, 'input>, name: &str, value: &str) -> Checked<()> {
        if self.attribute(nodes, name)? != value {
            return Err(bad("SIGNATURE_ALGORITHM", "Unsupported signature metadata"));
        }
        Ok(())
    }
    fn algorithm(&self, nodes: &Nodes<'_, 'input>, value: &str) -> Checked<()> {
        let node = self.one(nodes)?;
        if node.attribute("Algorithm") != Some(value)
            || node.children().any(|node| node.is_element())
        {
            return Err(bad(
                "SIGNATURE_ALGORITHM",
                "Unsupported algorithm or parameters",
            ));
        }
        Ok(())
    }
}
struct Verified {
    hash: String,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    certificate_signature: Vec<u8>,
}
fn decode(value: &str, maximum: usize, code: &'static str) -> Checked<Vec<u8>> {
    if value.len() > maximum * 2 {
        return Err(bad(code, "Encoded value exceeds the profile limit"));
    }
    let compact: String = value
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    let bytes = Base64::decode_vec(&compact).map_err(|_| bad(code, "Invalid base64 value"))?;
    if bytes.len() > maximum {
        return Err(bad(code, "Decoded value exceeds the profile limit"));
    }
    Ok(bytes)
}
fn signature(xml: &Xml<'_>, input: &str) -> Checked<Verified> {
    let signature = xml.one(&xml.signature())?;
    if (xml.all(DS, "Signature")).0 != vec![signature] {
        return Err(bad(
            "SIGNATURE_STRUCTURE",
            "Signature must be unique and anchored in the UBL signature extension",
        ));
    }
    let mut ids = BTreeSet::new();
    for node in xml.doc.descendants().filter(Node::is_element) {
        for attr in node.attributes().filter(|attr| {
            (attr.namespace().is_none() && matches!(attr.name(), "Id" | "ID" | "id"))
                || (attr.namespace() == Some("http://www.w3.org/XML/1998/namespace")
                    && attr.name() == "id")
        }) {
            let id = attr.value();
            if id.is_empty() || !ids.insert(id.to_owned()) {
                return Err(bad(
                    "SIGNATURE_DUPLICATE_ID",
                    "Signature reference IDs must be nonempty and unique",
                ));
            }
        }
    }
    let signature_id = signature
        .attribute("Id")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| bad("SIGNATURE_STRUCTURE", "Signature Id is required"))?;
    let info = xml.signature().children(DS, "SignedInfo");
    xml.one(&info)?;
    xml.algorithm(&info.children(DS, "CanonicalizationMethod"), C14N)?;
    xml.algorithm(
        &info.children(DS, "SignatureMethod"),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    )?;
    let references = (info.children(DS, "Reference")).0;
    if references.len() != 2 {
        return Err(bad(
            "SIGNATURE_REFERENCES",
            "Exactly two signature references are required",
        ));
    }
    let invoice = info
        .children(DS, "Reference")
        .filter(|node| node.attribute("Id") == Some("invoiceSignedData"));
    xml.one(&invoice)?;
    xml.expect_attribute(&invoice, "URI", "")?;
    xml.algorithm(&invoice.children(DS, "DigestMethod"), SHA256)?;
    let transforms = (invoice.children(DS, "Transforms").children(DS, "Transform")).0;
    if transforms.len() != 4 {
        return Err(bad(
            "SIGNATURE_TRANSFORMS",
            "Exactly three exclusion transforms followed by C14N 1.1 are required",
        ));
    }
    for (index, expression, prefixes) in [
        (
            1,
            "not(//ancestor-or-self::ext:UBLExtensions)",
            vec![("ext", EXT)],
        ),
        (
            2,
            "not(//ancestor-or-self::cac:Signature)",
            vec![("cac", CAC)],
        ),
        (
            3,
            "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])",
            vec![("cac", CAC), ("cbc", CBC)],
        ),
    ] {
        let transform = invoice
            .children(DS, "Transforms")
            .children(DS, "Transform")
            .at(index - 1);
        xml.expect_attribute(
            &transform,
            "Algorithm",
            "http://www.w3.org/TR/1999/REC-xpath-19991116",
        )?;
        xml.expect(&transform.children(DS, "XPath"), expression)?;
        if transforms[index - 1]
            .children()
            .filter(Node::is_element)
            .count()
            != 1
        {
            return Err(bad(
                "SIGNATURE_TRANSFORMS",
                "Unexpected transform parameters",
            ));
        }
        let xpath = xml.one(&transform.children(DS, "XPath"))?;
        for (prefix, uri) in prefixes {
            if xpath.lookup_namespace_uri(Some(prefix)) != Some(uri) {
                return Err(bad(
                    "SIGNATURE_TRANSFORMS",
                    "Transform namespace binding differs from the pinned profile",
                ));
            }
        }
    }
    xml.algorithm(
        &invoice
            .children(DS, "Transforms")
            .children(DS, "Transform")
            .at(3),
        C14N,
    )?;
    let properties = xml
        .signature()
        .children(DS, "Object")
        .children(XADES, "QualifyingProperties")
        .children(XADES, "SignedProperties");
    let property_node = xml.one(&properties)?;
    let property_id = property_node
        .attribute("Id")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| bad("SIGNATURE_REFERENCES", "SignedProperties Id is required"))?;
    let qualifier = xml
        .signature()
        .children(DS, "Object")
        .children(XADES, "QualifyingProperties");
    let target = xml.attribute(&qualifier, "Target")?;
    if target != signature_id && target != format!("#{signature_id}") {
        return Err(bad(
            "SIGNATURE_REFERENCES",
            "QualifyingProperties does not target this signature",
        ));
    }
    let properties_reference = references
        .iter()
        .find(|r| r.attribute("Id") != Some("invoiceSignedData"))
        .ok_or_else(|| {
            bad(
                "SIGNATURE_REFERENCES",
                "SignedProperties reference is missing",
            )
        })?;
    if properties_reference.attribute("URI") != Some(format!("#{property_id}").as_str())
        || properties_reference.attribute("Type")
            != Some("http://www.w3.org/2000/09/xmldsig#SignatureProperties")
    {
        return Err(bad(
            "SIGNATURE_REFERENCES",
            "SignedProperties reference is not bound to the selected subtree",
        ));
    }
    let ref_path = info
        .children(DS, "Reference")
        .filter(|node| node.attribute("Id") != Some("invoiceSignedData"));
    xml.algorithm(&ref_path.children(DS, "DigestMethod"), SHA256)?;
    if !ref_path.children(DS, "Transforms").0.is_empty() {
        return Err(bad(
            "SIGNATURE_TRANSFORMS",
            "SignedProperties transforms are unsupported by this profile",
        ));
    }
    // The SDK signs the invoice digest bytes with ECDSA-SHA256 (a second SHA256),
    // rather than a generic XMLDSig SignedInfo preimage. Reference checks remain
    // explicit and no invoice-controlled algorithm is executed.
    let hash = integrity_xml::invoice_digest(input).map_err(CheckError::Backend)?;
    if decode(
        &xml.text(&invoice.children(DS, "DigestValue"))?,
        32,
        "SIGNATURE_DIGEST",
    )? != decode(&hash, 32, "SIGNATURE_DIGEST")?
    {
        return Err(bad(
            "SIGNATURE_DIGEST",
            "Invoice digest does not match the original XML",
        ));
    }
    let preimage = integrity_xml::properties_preimage(input).map_err(CheckError::Backend)?;
    let expected = format!("{:x}", Sha256::digest(preimage.as_bytes()));
    if decode(
        &xml.text(&ref_path.children(DS, "DigestValue"))?,
        64,
        "SIGNED_PROPERTIES_DIGEST",
    )? != expected.as_bytes()
    {
        return Err(bad(
            "SIGNED_PROPERTIES_DIGEST",
            "SignedProperties digest does not match its original subtree",
        ));
    }
    let certificate_path = xml
        .signature()
        .children(DS, "KeyInfo")
        .children(DS, "X509Data")
        .children(DS, "X509Certificate");
    if (xml.all(DS, "X509Certificate")).0.len() != 1 {
        return Err(bad(
            "SIGNATURE_CERTIFICATE",
            "Exactly one embedded signing certificate is required",
        ));
    }
    let certificate_bytes = decode(
        &xml.text(&certificate_path)?,
        16 * 1024,
        "SIGNATURE_CERTIFICATE",
    )?;
    let certificate = Certificate::from_der(&certificate_bytes)
        .map_err(|_| bad("SIGNATURE_CERTIFICATE", "Invalid DER signing certificate"))?;
    let spki = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| CheckError::Backend(e.to_string()))?;
    let key = VerifyingKey::from_public_key_der(&spki).map_err(|_| {
        bad(
            "SIGNATURE_CERTIFICATE",
            "Signing key must be a secp256k1 EC public key",
        )
    })?;
    let signature_bytes = decode(
        &xml.text(&xml.signature().children(DS, "SignatureValue"))?,
        80,
        "SIGNATURE_VALUE",
    )?;
    let value = Signature::from_der(&signature_bytes)
        .map_err(|_| bad("SIGNATURE_VALUE", "Invalid DER ECDSA signature"))?
        .normalize_s();
    key.verify(&decode(&hash, 32, "SIGNATURE_DIGEST")?, &value)
        .map_err(|_| {
            bad(
                "SIGNATURE_VALUE",
                "ECDSA signature does not verify with the embedded certificate",
            )
        })?;
    let certificate_properties = properties
        .children(XADES, "SignedSignatureProperties")
        .children(XADES, "SigningCertificate")
        .children(XADES, "Cert");
    xml.text(
        &properties
            .children(XADES, "SignedSignatureProperties")
            .children(XADES, "SigningTime"),
    )?;
    xml.one(&certificate_properties)?;
    xml.algorithm(
        &certificate_properties
            .children(XADES, "CertDigest")
            .children(DS, "DigestMethod"),
        SHA256,
    )?;
    let digest = format!(
        "{:x}",
        Sha256::digest(Base64::encode_string(&certificate_bytes).as_bytes())
    );
    if decode(
        &xml.text(
            &certificate_properties
                .children(XADES, "CertDigest")
                .children(DS, "DigestValue"),
        )?,
        64,
        "SIGNATURE_CERTIFICATE_DIGEST",
    )? != digest.as_bytes()
    {
        return Err(bad(
            "SIGNATURE_CERTIFICATE_DIGEST",
            "Signing certificate digest differs",
        ));
    }
    let issuer = xml.text(
        &certificate_properties
            .children(XADES, "IssuerSerial")
            .children(DS, "X509IssuerName"),
    )?;
    let expected_issuer = certificate.tbs_certificate().issuer().to_string();
    let sdk_issuer = expected_issuer
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(", ");
    if issuer != expected_issuer && issuer != sdk_issuer {
        return Err(bad(
            "SIGNATURE_CERTIFICATE_ISSUER",
            "Certificate issuer name differs",
        ));
    }
    let serial = xml.text(
        &certificate_properties
            .children(XADES, "IssuerSerial")
            .children(DS, "X509SerialNumber"),
    )?;
    let serial = serial.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if serial.is_empty()
        || !serial.bytes().all(|b| b.is_ascii_digit())
        || num_bigint::BigUint::parse_bytes(serial.as_bytes(), 10)
            != Some(num_bigint::BigUint::from_bytes_be(
                certificate.tbs_certificate().serial_number().as_bytes(),
            ))
    {
        return Err(bad(
            "SIGNATURE_CERTIFICATE_SERIAL",
            "Certificate serial number differs",
        ));
    }
    let certificate_signature = certificate
        .signature()
        .as_bytes()
        .ok_or_else(|| {
            bad(
                "SIGNATURE_CERTIFICATE",
                "Certificate signature is not byte-aligned",
            )
        })?
        .to_vec();
    Ok(Verified {
        hash,
        signature: signature_bytes,
        public_key: spki,
        certificate_signature,
    })
}

/// Both binary SHA256 and the SDK's initial base64(hex(SHA256("0"))) are used.
pub(super) fn valid_previous_hash(value: &str) -> bool {
    if value.len() > 88 {
        return false;
    }
    Base64::decode_vec(value).is_ok_and(|bytes| {
        bytes.len() == 32 || (bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit))
    })
}
fn previous_hash(xml: &Xml<'_>, expected: Option<&str>) -> Checked<()> {
    let actual = xml.text(&xml.document_reference("PIH"))?;
    if !valid_previous_hash(&actual) {
        return Err(bad(
            "PIH_FORMAT",
            "Previous invoice hash is not a canonical SHA-256 representation",
        ));
    }
    if expected.is_some_and(|value| value != actual) {
        return Err(bad(
            "PIH_MISMATCH",
            "Previous invoice hash differs from the supplied predecessor",
        ));
    }
    Ok(())
}
fn qr_tags(bytes: &[u8]) -> Checked<BTreeMap<u8, Vec<u8>>> {
    let mut tags = BTreeMap::new();
    let mut at = 0;
    let mut previous = 0;
    while at < bytes.len() {
        if bytes.len() - at < 2 {
            return Err(bad("QR_TLV", "Truncated QR tag header"));
        }
        let tag = bytes[at];
        let length = bytes[at + 1] as usize;
        at += 2;
        if tag <= previous || tag > 9 || tag == 0 || length == 0 || length > bytes.len() - at {
            return Err(bad("QR_TLV", "Invalid QR tag order, number, or length"));
        }
        tags.insert(tag, bytes[at..at + length].to_vec());
        at += length;
        previous = tag;
    }
    if !(1..=9).all(|tag| tags.contains_key(&tag)) {
        return Err(bad(
            "QR_TLV",
            "Simplified invoice QR requires tags 1 through 9",
        ));
    }
    Ok(tags)
}
fn qr(xml: &Xml<'_>, verified: &Verified) -> Checked<()> {
    qr_for_profile(xml, verified, QrProfile::Sdk)
}
enum QrProfile {
    Sdk,
    Signing,
}

fn qr_for_profile(xml: &Xml<'_>, verified: &Verified, profile: QrProfile) -> Checked<()> {
    // Signing uses XML scalar normalization from QR construction. Free-text
    // seller names and the public SDK comparison retain their original bytes.
    let scalar = |field: crate::invoice::qr::QrField, value: String| match profile {
        QrProfile::Sdk => value,
        QrProfile::Signing => field.normalize(&value).to_owned(),
    };
    let encoded = xml.text(&xml.document_reference("QR"))?;
    let tags = qr_tags(&decode(&encoded, 4096, "QR_BASE64")?)?;
    let expected = [
        (
            1,
            xml.text(
                &xml.root()
                    .children(CAC, "AccountingSupplierParty")
                    .children(CAC, "Party")
                    .children(CAC, "PartyLegalEntity")
                    .children(CBC, "RegistrationName"),
            )?
            .into_bytes(),
        ),
        (
            2,
            scalar(
                crate::invoice::qr::QrField::SellerVat,
                xml.text(
                    &xml.root()
                        .children(CAC, "AccountingSupplierParty")
                        .children(CAC, "Party")
                        .children(CAC, "PartyTaxScheme")
                        .children(CBC, "CompanyID"),
                )?,
            )
            .into_bytes(),
        ),
        // QR tag 4 includes prepayment and payable rounding adjustments (BT-115).
        (
            4,
            scalar(
                crate::invoice::qr::QrField::TotalWithVat,
                xml.text(
                    &xml.root()
                        .children(CAC, "LegalMonetaryTotal")
                        .children(CBC, "PayableAmount"),
                )?,
            )
            .into_bytes(),
        ),
        (6, verified.hash.as_bytes().to_vec()),
        (7, Base64::encode_string(&verified.signature).into_bytes()),
        (8, verified.public_key.clone()),
        (9, verified.certificate_signature.clone()),
    ];
    for (tag, value) in expected {
        if tags.get(&tag) != Some(&value) {
            return Err(bad(
                "QR_VALUE",
                format!("QR tag {tag} does not match the invoice or signing certificate"),
            ));
        }
    }
    let time = std::str::from_utf8(&tags[&3])
        .map_err(|_| bad("QR_TIMESTAMP", "QR timestamp is not UTF-8"))?;
    let expected_time = format!(
        "{}T{}",
        scalar(
            crate::invoice::qr::QrField::IssueDate,
            xml.text(&xml.root().children(CBC, "IssueDate"))?
        ),
        scalar(
            crate::invoice::qr::QrField::IssueTime,
            xml.text(&xml.root().children(CBC, "IssueTime"))?
        )
    );
    // SDK-QR-002: the SDK ignores malformed suffixes. Require a complete
    // timestamp and compare instants; absent offsets mean UTC in this profile.
    let timestamp = |value: &str| {
        if value.len() > 128 {
            return None;
        }
        chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .or_else(|| chrono::DateTime::parse_from_rfc3339(&format!("{value}Z")).ok())
    };
    if timestamp(time)
        .zip(timestamp(&expected_time))
        .is_none_or(|(a, b)| a != b)
    {
        return Err(bad(
            "QR_TIMESTAMP",
            "QR timestamp differs from the invoice issue timestamp",
        ));
    }
    let vat =
        std::str::from_utf8(&tags[&5]).map_err(|_| bad("QR_VAT", "QR VAT amount is not UTF-8"))?;
    let xml_vat = xml.text(
        &xml.root()
            .children(CAC, "TaxTotal")
            .children(CBC, "TaxAmount")
            .at(0),
    )?;
    // SDK-QR-003: require exact decimal equality, rejecting NaN, exponents,
    // and distinct values that collapse to the same binary float.
    let equal =
        super::business_rules::decimal_equal(vat, &xml_vat).map_err(|error| match error {
            super::business_rules::FailureKind::Limit(_) => CheckError::Backend(error.to_string()),
            _ => bad("QR_VAT", "QR VAT amount is not an XML decimal"),
        })?;
    if !equal {
        return Err(bad(
            "QR_VAT",
            "QR VAT amount differs from the invoice VAT amount",
        ));
    }
    Ok(())
}
fn record(
    report: &mut ZatcaValidationReport,
    stage: ZatcaStage,
    result: Checked<()>,
) -> Result<(), (ZatcaStage, String)> {
    let result_stage = report
        .stages
        .iter_mut()
        .find(|s| s.stage == stage)
        .expect("pipeline stage");
    result_stage.status = ZatcaStageStatus::Completed;
    match result {
        Ok(()) => Ok(()),
        Err(CheckError::Backend(message)) => Err((stage, message)),
        Err(CheckError::Violation(code, message)) => {
            result_stage.findings.push(ZatcaFinding {
                assertion_site: None,
                finding: ValidationFinding {
                    layer: match stage {
                        ZatcaStage::Signature => ValidationLayer::Signature,
                        ZatcaStage::Qr => ValidationLayer::Qr,
                        _ => ValidationLayer::PreviousInvoiceHash,
                    },
                    code: code.into(),
                    severity: Severity::Error,
                    message,
                    location: None,
                },
            });
            Ok(())
        }
    }
}
pub(super) fn apply(
    input: &str,
    previous: Option<&str>,
    report: &mut ZatcaValidationReport,
) -> Result<(), (ZatcaStage, String)> {
    let xml = Xml::parse(input).map_err(|e| (ZatcaStage::Signature, e))?;
    let transaction = xml.attribute(&xml.root().children(CBC, "InvoiceTypeCode"), "name");
    match transaction {
        Ok(value) if value.starts_with("01") => {
            for stage in &mut report.stages {
                if matches!(stage.stage, ZatcaStage::Signature | ZatcaStage::Qr) {
                    stage.status = ZatcaStageStatus::NotApplicable;
                }
            }
        }
        Ok(value) if value.starts_with("02") => match signature(&xml, input) {
            Ok(verified) => {
                record(report, ZatcaStage::Signature, Ok(()))?;
                record(report, ZatcaStage::Qr, qr(&xml, &verified))?;
            }
            Err(error) => {
                record(report, ZatcaStage::Signature, Err(error))?;
            }
        },
        Ok(_) => record(
            report,
            ZatcaStage::Signature,
            Err(bad(
                "SIGNATURE_APPLICABILITY",
                "Invoice transaction code does not identify a supported standard or simplified profile",
            )),
        )?,
        Err(error) => record(report, ZatcaStage::Signature, Err(error))?,
    }
    record(
        report,
        ZatcaStage::PreviousInvoiceHash,
        previous_hash(&xml, previous),
    )?;
    if previous.is_none() {
        let stage = report
            .stages
            .iter_mut()
            .find(|s| s.stage == ZatcaStage::PreviousInvoiceHash)
            .unwrap();
        stage.status = ZatcaStageStatus::ContextRequired;
        stage.findings.push(ZatcaFinding {
            assertion_site: None,
            finding: ValidationFinding {
                layer: ValidationLayer::PreviousInvoiceHash,
                code: "PIH_CONTEXT_REQUIRED".into(),
                severity: Severity::Warning,
                message: "Supply previous_invoice_hash to verify predecessor continuity".into(),
                location: None,
            },
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "integrity_tests.rs"]
mod tests;

pub(crate) fn signing_postcondition(
    input: &str,
    intended: &crate::invoice::sign::SignedProperties,
    certificate: &[u8],
    qr_payload: &str,
) -> Result<(), String> {
    let xml = Xml::parse(input)?;
    let checked = || -> Checked<()> {
        let verified = signature(&xml, input)?;
        if verified.hash != intended.invoice_hash()
            || verified.signature
                != Base64::decode_vec(intended.signature())
                    .map_err(|_| bad("SIGNING_POSTCONDITION", "invalid intended signature"))?
        {
            return Err(bad(
                "SIGNING_POSTCONDITION",
                "final invoice digest or signature differs",
            ));
        }
        let embedded = xml.text(
            &xml.signature()
                .children(DS, "KeyInfo")
                .children(DS, "X509Data")
                .children(DS, "X509Certificate"),
        )?;
        if decode(&embedded, 16 * 1024, "SIGNING_POSTCONDITION")? != certificate {
            return Err(bad("SIGNING_POSTCONDITION", "final certificate differs"));
        }
        let time = xml.text(
            &xml.signature()
                .children(DS, "Object")
                .children(XADES, "QualifyingProperties")
                .children(XADES, "SignedProperties")
                .children(XADES, "SignedSignatureProperties")
                .children(XADES, "SigningTime"),
        )?;
        if time != intended.signing_time() || xml.text(&xml.document_reference("QR"))? != qr_payload
        {
            return Err(bad(
                "SIGNING_POSTCONDITION",
                "final signing time or QR differs",
            ));
        }
        qr_for_profile(&xml, &verified, QrProfile::Signing)
    };
    checked().map_err(|e| format!("signing postcondition: {e:?}"))
}
