//! Independent test readers/verifiers. Never call the production signer or QR parser here.
use base64ct::{Base64, Encoding};
use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use roxmltree::Document;
#[path = "xml.rs"]
#[allow(dead_code)]
mod test_xml;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub use test_xml::select;
pub fn replace_text(xml: &str, path: &str, value: &str) -> String {
    test_xml::replace_text(xml, path, value)
}
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

pub fn document(xml: &str) -> Result<Document<'_>, String> {
    Document::parse(xml).map_err(|e| format!("XML: {e}"))
}
pub fn context<'a, 'input>(doc: &'a Document<'input>) -> &'a Document<'input> {
    doc
}
pub fn text(doc: &Document<'_>, expr: &str) -> Result<String, String> {
    test_xml::text(doc, expr)
}
pub fn decode(value: &str) -> Result<Vec<u8>, String> {
    Base64::decode_vec(value).map_err(|e| format!("base64: {e}"))
}

pub fn tlv(bytes: &[u8]) -> Result<BTreeMap<u8, Vec<u8>>, String> {
    let mut tags = BTreeMap::new();
    let mut cursor = 0;
    let mut previous = 0;
    while cursor < bytes.len() {
        if cursor + 2 > bytes.len() {
            return Err("truncated TLV header".into());
        }
        let tag = bytes[cursor];
        let len = bytes[cursor + 1] as usize;
        cursor += 2;
        if tag <= previous || tag > 9 || cursor + len > bytes.len() {
            return Err("invalid TLV tag/order/length".into());
        }
        tags.insert(tag, bytes[cursor..cursor + len].to_vec());
        previous = tag;
        cursor += len;
    }
    for tag in 1..=8 {
        if !tags.contains_key(&tag) {
            return Err(format!("missing QR tag {tag}"));
        }
    }
    Ok(tags)
}

pub fn qr(ctx: &Document<'_>) -> Result<BTreeMap<u8, Vec<u8>>, String> {
    tlv(&decode(&text(
        ctx,
        "//cac:AdditionalDocumentReference[cbc:ID='QR']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject",
    )?)?)
}

/// SDK 238-R3.4.8 signs SHA256(invoice-digest bytes) with ECDSA; the
/// verifier's message API hashes once. Captured SDK signatures prove this contract.
pub fn verify_signed(
    xml: &str,
    expected_hash: &str,
    expected_certificate: &[u8],
) -> Result<(), String> {
    let doc = document(xml)?;
    let ctx = context(&doc);
    let hash = text(
        ctx,
        "//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue",
    )?;
    if hash != expected_hash {
        return Err("invoice digest differs".into());
    }
    let cert_bytes = decode(&text(ctx, "//ds:X509Certificate")?)?;
    if cert_bytes != expected_certificate {
        return Err("certificate differs".into());
    }
    let cert = Certificate::from_der(&cert_bytes).map_err(|e| e.to_string())?;
    let spki = cert.tbs_certificate().subject_public_key_info();
    let verifying =
        VerifyingKey::from_sec1_bytes(spki.subject_public_key.as_bytes().ok_or("unaligned key")?)
            .map_err(|e| e.to_string())?;
    let signature_bytes = decode(&text(ctx, "//ds:SignatureValue")?)?;
    let signature = Signature::from_der(&signature_bytes).map_err(|e| e.to_string())?;
    // Accept both mathematically equivalent high-S/low-S encodings from independent signers.
    let signature = signature.normalize_s();
    verifying
        .verify(&decode(&hash)?, &signature)
        .map_err(|e| format!("signature: {e}"))?;
    let cert_digest = Base64::encode_string(
        format!(
            "{:x}",
            Sha256::digest(Base64::encode_string(&cert_bytes).as_bytes())
        )
        .as_bytes(),
    );
    if text(ctx, "//xades:CertDigest/ds:DigestValue")? != cert_digest {
        return Err("certificate digest".into());
    }
    let tags = qr(ctx)?;
    let expected = [
        (
            1,
            text(
                ctx,
                "//cac:AccountingSupplierParty//cac:PartyLegalEntity/cbc:RegistrationName",
            )?
            .into_bytes(),
        ),
        (
            2,
            text(
                ctx,
                "//cac:AccountingSupplierParty//cac:PartyTaxScheme/cbc:CompanyID",
            )?
            .into_bytes(),
        ),
        (
            3,
            format!(
                "{}T{}",
                text(ctx, "/*/cbc:IssueDate")?,
                text(ctx, "/*/cbc:IssueTime")?
            )
            .into_bytes(),
        ),
        (
            4,
            text(ctx, "//cac:LegalMonetaryTotal/cbc:PayableAmount")?.into_bytes(),
        ),
        (
            5,
            text(ctx, "(/*/cac:TaxTotal/cbc:TaxAmount)[1]")?.into_bytes(),
        ),
        (6, hash.into_bytes()),
        (7, Base64::encode_string(&signature_bytes).into_bytes()),
        (8, spki.to_der().map_err(|e| e.to_string())?),
    ];
    for (tag, value) in expected {
        if tags.get(&tag) != Some(&value) {
            return Err(format!("QR tag {tag} differs"));
        }
    }
    if let Some(value) = tags.get(&9)
        && value.as_slice()
            != cert
                .signature()
                .as_bytes()
                .ok_or("unaligned cert signature")?
    {
        return Err("QR certificate signature differs".into());
    }
    if text(ctx, "/*/cbc:InvoiceTypeCode/@name")?.starts_with("02") && !tags.contains_key(&9) {
        return Err("missing simplified QR certificate signature".into());
    }
    let transforms = select(
        ctx,
        "//ds:Reference[@Id='invoiceSignedData']/ds:Transforms/ds:Transform",
    );
    if transforms.len() != 4 {
        return Err("signature transform count".into());
    }
    for (index, predicate) in [
        "not(//ancestor-or-self::ext:UBLExtensions)",
        "not(//ancestor-or-self::cac:Signature)",
        "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])",
    ]
    .iter()
    .enumerate()
    {
        let base = format!(
            "//ds:Reference[@Id='invoiceSignedData']/ds:Transforms/ds:Transform[{}]",
            index + 1
        );
        if text(ctx, &format!("{base}/@Algorithm"))?
            != "http://www.w3.org/TR/1999/REC-xpath-19991116"
            || text(ctx, &format!("{base}/ds:XPath"))? != *predicate
        {
            return Err("signature exclusion transform".into());
        }
    }
    if text(
        ctx,
        "//ds:Reference[@Id='invoiceSignedData']/ds:Transforms/ds:Transform[4]/@Algorithm",
    )? != "http://www.w3.org/2006/12/xml-c14n11"
    {
        return Err("signature canonicalization transform".into());
    }
    let time = text(ctx, "//xades:SigningTime")?;
    chrono::NaiveDateTime::parse_from_str(&time, "%Y-%m-%dT%H:%M:%S")
        .map_err(|e| format!("signing time: {e}"))?;
    for (expr, expected) in [
        (
            "//ds:CanonicalizationMethod/@Algorithm",
            "http://www.w3.org/2006/12/xml-c14n11",
        ),
        (
            "//ds:SignatureMethod/@Algorithm",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        ),
        ("//ds:Reference[@Id='invoiceSignedData']/@URI", ""),
        (
            "//ds:Reference[@URI='#xadesSignedProperties']/ds:DigestMethod/@Algorithm",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ),
    ] {
        if text(ctx, expr)? != expected {
            return Err(format!("signature metadata: {expr}"));
        }
    }
    Ok(())
}

/// Read the actual subtree without rebuilding production's template. DOM4J's
/// standalone serialization adds inherited declarations at their first use.
/// Captured SDK preimages independently test these namespace/whitespace rules.
pub fn properties_preimage(xml: &str) -> Result<String, String> {
    let doc = document(xml)?;
    let ctx = context(&doc);
    let nodes = select(ctx, "//xades:SignedProperties");
    if nodes.len() != 1 {
        return Err("SignedProperties count".into());
    }
    let mut raw = xml[nodes[0].range()].to_owned();
    if !raw.starts_with("<xades:SignedProperties xmlns:xades=") {
        raw = raw.replacen(
            "<xades:SignedProperties ",
            "<xades:SignedProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" ",
            1,
        );
    }
    for name in [
        "DigestMethod",
        "DigestValue",
        "X509IssuerName",
        "X509SerialNumber",
    ] {
        let tag = format!("<ds:{name}");
        let declared = format!("{tag} xmlns:ds=");
        if !raw.contains(&declared) {
            raw = raw.replace(
                &tag,
                &format!("{tag} xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""),
            );
        }
    }
    Ok(raw)
}

pub fn verify_references(xml: &str) -> Result<(), String> {
    let doc = document(xml)?;
    let ctx = context(&doc);
    let properties_hash = text(
        ctx,
        "//ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue",
    )?;
    let bytes = properties_preimage(xml)?;
    if properties_hash
        != Base64::encode_string(format!("{:x}", Sha256::digest(bytes.as_bytes())).as_bytes())
    {
        return Err("SignedProperties digest".into());
    }
    let expected = text(
        ctx,
        "//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue",
    )?;
    let mut ranges: Vec<_> = doc.descendants().filter(|node| {
        let name = node.tag_name();
        (name.namespace() == Some("urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2") && name.name() == "UBLExtensions")
            || (name.namespace() == Some("urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2") && (name.name() == "Signature" || (name.name() == "AdditionalDocumentReference" && node.children().any(|child| child.tag_name().namespace() == Some("urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2") && child.tag_name().name() == "ID" && test_xml::content(child) == "QR"))))
    }).map(|node| node.range()).collect();
    ranges.sort_by_key(|range| (range.start, std::cmp::Reverse(range.end)));
    let mut retained: Vec<std::ops::Range<usize>> = Vec::new();
    for range in ranges {
        if !retained
            .last()
            .is_some_and(|parent| parent.end >= range.end)
        {
            retained.push(range);
        }
    }
    let mut filtered = xml.to_owned();
    for range in retained.into_iter().rev() {
        filtered.replace_range(range, "");
    }
    let canonical = xml_sec::c14n::canonicalize_xml_with_backend(
        filtered.as_bytes(),
        &xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Inclusive1_1, false),
        xml_sec::XmlBackend::Roxmltree,
    )
    .map_err(|e| e.to_string())?;
    if expected != Base64::encode_string(&Sha256::digest(&canonical)) {
        return Err("signed content digest".into());
    }
    Ok(())
}
