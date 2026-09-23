//! Local integrity checks for the pinned SDK profile, without issuer trust claims.
use super::{
    Severity, ValidationFinding, ValidationLayer, ZatcaFinding, ZatcaStage, ZatcaStageStatus,
    ZatcaValidationReport, integrity_xml,
};
use base64ct::{Base64, Encoding};
use k256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use libxml::{
    parser::{Parser, ParserOptions},
    tree::{Document, Node},
    xpath::Context,
};
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
const SIGNATURE: &str = "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature";
const PIH: &str = "/ubl:Invoice/cac:AdditionalDocumentReference[cbc:ID='PIH']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject";
const QR: &str = "/ubl:Invoice/cac:AdditionalDocumentReference[cbc:ID='QR']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject";
#[derive(Debug)]
enum CheckError {
    Violation(&'static str, String),
    Backend(String),
}
type Checked<T> = Result<T, CheckError>;
fn bad(code: &'static str, message: impl Into<String>) -> CheckError {
    CheckError::Violation(code, message.into())
}
struct Xml {
    _doc: Document,
    ctx: Context,
}
impl Xml {
    fn parse(xml: &str) -> Result<Self, String> {
        super::business_rules::check_input(xml).map_err(|e| e.to_string())?;
        let doc = Parser::default()
            .parse_string_with_options(
                xml,
                ParserOptions {
                    recover: false,
                    no_net: true,
                    huge: false,
                    ..Default::default()
                },
            )
            .map_err(|e| e.to_string())?;
        let ctx = Context::new(&doc).map_err(|_| "could not create integrity XML context")?;
        for (prefix, uri) in [
            ("ubl", UBL),
            ("cbc", CBC),
            ("cac", CAC),
            ("ext", EXT),
            ("ds", DS),
            ("xades", XADES),
            (
                "sig",
                "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2",
            ),
            (
                "sac",
                "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2",
            ),
            ("xml", "http://www.w3.org/XML/1998/namespace"),
        ] {
            ctx.register_namespace(prefix, uri)
                .map_err(|_| "could not register integrity XML namespace")?;
        }
        Ok(Self { _doc: doc, ctx })
    }
    fn nodes(&self, path: &str) -> Checked<Vec<Node>> {
        self.ctx
            .evaluate(path)
            .map(|v| v.get_nodes_as_vec())
            .map_err(|_| CheckError::Backend("integrity XML selection failed".into()))
    }
    fn one(&self, path: &str) -> Checked<Node> {
        let nodes = self.nodes(path)?;
        if nodes.len() != 1 {
            return Err(bad(
                "INTEGRITY_STRUCTURE",
                format!("Expected exactly one {path}; found {}", nodes.len()),
            ));
        }
        Ok(nodes[0].clone())
    }
    fn text(&self, path: &str) -> Checked<String> {
        let node = self.one(path)?;
        if !node.get_child_elements().is_empty() {
            return Err(bad(
                "INTEGRITY_STRUCTURE",
                format!("Expected a scalar value at {path}"),
            ));
        }
        Ok(node.get_content())
    }
    fn expect(&self, path: &str, value: &str) -> Checked<()> {
        if self.text(path)? != value {
            return Err(bad(
                "SIGNATURE_ALGORITHM",
                format!("Unsupported signature metadata at {path}"),
            ));
        }
        Ok(())
    }
    fn algorithm(&self, path: &str, value: &str) -> Checked<()> {
        let node = self.one(path)?;
        if node.get_property_no_ns("Algorithm").as_deref() != Some(value)
            || !node.get_child_elements().is_empty()
        {
            return Err(bad(
                "SIGNATURE_ALGORITHM",
                format!("Unsupported algorithm or parameters at {path}"),
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
fn signature(xml: &Xml, input: &str) -> Checked<Verified> {
    let signature = xml.one(SIGNATURE)?;
    if xml.nodes("//ds:Signature")? != vec![signature.clone()] {
        return Err(bad(
            "SIGNATURE_STRUCTURE",
            "Signature must be unique and anchored in the UBL signature extension",
        ));
    }
    let mut ids = BTreeSet::new();
    for attr in xml.nodes("//@Id | //@ID | //@id | //@xml:id")? {
        let id = attr.get_content();
        if id.is_empty() || !ids.insert(id) {
            return Err(bad(
                "SIGNATURE_DUPLICATE_ID",
                "Signature reference IDs must be nonempty and unique",
            ));
        }
    }
    let signature_id = signature
        .get_property_no_ns("Id")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| bad("SIGNATURE_STRUCTURE", "Signature Id is required"))?;
    let info = format!("{SIGNATURE}/ds:SignedInfo");
    xml.one(&info)?;
    xml.algorithm(&format!("{info}/ds:CanonicalizationMethod"), C14N)?;
    xml.algorithm(
        &format!("{info}/ds:SignatureMethod"),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    )?;
    let references = xml.nodes(&format!("{info}/ds:Reference"))?;
    if references.len() != 2 {
        return Err(bad(
            "SIGNATURE_REFERENCES",
            "Exactly two signature references are required",
        ));
    }
    let invoice = format!("{info}/ds:Reference[@Id='invoiceSignedData']");
    xml.one(&invoice)?;
    xml.expect(&format!("{invoice}/@URI"), "")?;
    xml.algorithm(&format!("{invoice}/ds:DigestMethod"), SHA256)?;
    let transforms = xml.nodes(&format!("{invoice}/ds:Transforms/ds:Transform"))?;
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
        let transform = format!("{invoice}/ds:Transforms/ds:Transform[{index}]");
        xml.expect(
            &format!("{transform}/@Algorithm"),
            "http://www.w3.org/TR/1999/REC-xpath-19991116",
        )?;
        xml.expect(&format!("{transform}/ds:XPath"), expression)?;
        if transforms[index - 1].get_child_elements().len() != 1 {
            return Err(bad(
                "SIGNATURE_TRANSFORMS",
                "Unexpected transform parameters",
            ));
        }
        let xpath = xml.one(&format!("{transform}/ds:XPath"))?;
        for (prefix, uri) in prefixes {
            if xpath.lookup_namespace_uri(prefix).as_deref() != Some(uri) {
                return Err(bad(
                    "SIGNATURE_TRANSFORMS",
                    "Transform namespace binding differs from the pinned profile",
                ));
            }
        }
    }
    xml.algorithm(&format!("{invoice}/ds:Transforms/ds:Transform[4]"), C14N)?;
    let properties =
        format!("{SIGNATURE}/ds:Object/xades:QualifyingProperties/xades:SignedProperties");
    let property_node = xml.one(&properties)?;
    let property_id = property_node
        .get_property_no_ns("Id")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| bad("SIGNATURE_REFERENCES", "SignedProperties Id is required"))?;
    let qualifier = format!("{SIGNATURE}/ds:Object/xades:QualifyingProperties");
    let target = xml.text(&format!("{qualifier}/@Target"))?;
    if target != signature_id && target != format!("#{signature_id}") {
        return Err(bad(
            "SIGNATURE_REFERENCES",
            "QualifyingProperties does not target this signature",
        ));
    }
    let properties_reference = references
        .iter()
        .find(|r| r.get_property_no_ns("Id").as_deref() != Some("invoiceSignedData"))
        .ok_or_else(|| {
            bad(
                "SIGNATURE_REFERENCES",
                "SignedProperties reference is missing",
            )
        })?;
    if properties_reference.get_property_no_ns("URI") != Some(format!("#{property_id}"))
        || properties_reference.get_property_no_ns("Type").as_deref()
            != Some("http://www.w3.org/2000/09/xmldsig#SignatureProperties")
    {
        return Err(bad(
            "SIGNATURE_REFERENCES",
            "SignedProperties reference is not bound to the selected subtree",
        ));
    }
    let ref_path = format!("{info}/ds:Reference[not(@Id='invoiceSignedData')]");
    xml.algorithm(&format!("{ref_path}/ds:DigestMethod"), SHA256)?;
    if !xml.nodes(&format!("{ref_path}/ds:Transforms"))?.is_empty() {
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
        &xml.text(&format!("{invoice}/ds:DigestValue"))?,
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
        &xml.text(&format!("{ref_path}/ds:DigestValue"))?,
        64,
        "SIGNED_PROPERTIES_DIGEST",
    )? != expected.as_bytes()
    {
        return Err(bad(
            "SIGNED_PROPERTIES_DIGEST",
            "SignedProperties digest does not match its original subtree",
        ));
    }
    let certificate_path = format!("{SIGNATURE}/ds:KeyInfo/ds:X509Data/ds:X509Certificate");
    if xml.nodes("//ds:X509Certificate")?.len() != 1 {
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
        &xml.text(&format!("{SIGNATURE}/ds:SignatureValue"))?,
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
    let certificate_properties =
        format!("{properties}/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert");
    xml.text(&format!(
        "{properties}/xades:SignedSignatureProperties/xades:SigningTime"
    ))?;
    xml.one(&certificate_properties)?;
    xml.algorithm(
        &format!("{certificate_properties}/xades:CertDigest/ds:DigestMethod"),
        SHA256,
    )?;
    let digest = format!(
        "{:x}",
        Sha256::digest(Base64::encode_string(&certificate_bytes).as_bytes())
    );
    if decode(
        &xml.text(&format!(
            "{certificate_properties}/xades:CertDigest/ds:DigestValue"
        ))?,
        64,
        "SIGNATURE_CERTIFICATE_DIGEST",
    )? != digest.as_bytes()
    {
        return Err(bad(
            "SIGNATURE_CERTIFICATE_DIGEST",
            "Signing certificate digest differs",
        ));
    }
    let issuer = xml.text(&format!(
        "{certificate_properties}/xades:IssuerSerial/ds:X509IssuerName"
    ))?;
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
    let serial = xml.text(&format!(
        "{certificate_properties}/xades:IssuerSerial/ds:X509SerialNumber"
    ))?;
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
fn previous_hash(xml: &Xml, expected: Option<&str>) -> Checked<()> {
    let actual = xml.text(PIH)?;
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
fn qr(xml: &Xml, verified: &Verified) -> Checked<()> {
    let encoded = xml.text(QR)?;
    let tags = qr_tags(&decode(&encoded, 4096, "QR_BASE64")?)?;
    let expected=[
        (1,xml.text("/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName")?.into_bytes()),
        (2,xml.text("/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID")?.into_bytes()),
        // Pinned SDK compares tag4 to BT-115 (PayableAmount). The library's QR
        // generator follows the published TaxInclusiveAmount mapping instead;
        // SDK-QR-001 records that difference for payable rounding.
        (4,xml.text("/ubl:Invoice/cac:LegalMonetaryTotal/cbc:PayableAmount")?.into_bytes()),
        (6,verified.hash.as_bytes().to_vec()),
        (7,Base64::encode_string(&verified.signature).into_bytes()),
        (8,verified.public_key.clone()),
        (9,verified.certificate_signature.clone()),
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
        xml.text("/ubl:Invoice/cbc:IssueDate")?,
        xml.text("/ubl:Invoice/cbc:IssueTime")?
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
    let xml_vat = xml.text("(/ubl:Invoice/cac:TaxTotal/cbc:TaxAmount)[1]")?;
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
    let transaction = xml.text("/ubl:Invoice/cbc:InvoiceTypeCode/@name");
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
