//! Independent test readers/verifiers. Never call the production signer or QR parser here.
use base64ct::{Base64, Encoding};
use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use libxml::{
    parser::{Parser, ParserOptions},
    tree::Document,
    xpath::Context,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

pub fn document(xml: &str) -> Result<Document, String> {
    Parser::default()
        .parse_string_with_options(
            xml,
            ParserOptions {
                recover: false,
                ..Default::default()
            },
        )
        .map_err(|e| format!("XML: {e}"))
}
pub fn context(doc: &Document) -> Context {
    let ctx = Context::new(doc).unwrap();
    for (p, ns) in [
        ("ds", "http://www.w3.org/2000/09/xmldsig#"),
        ("xades", "http://uri.etsi.org/01903/v1.3.2#"),
        (
            "cbc",
            "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
        ),
        (
            "cac",
            "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
        ),
    ] {
        ctx.register_namespace(p, ns).unwrap();
    }
    ctx
}
pub fn text(ctx: &Context, expr: &str) -> Result<String, String> {
    let nodes = ctx
        .evaluate(expr)
        .map_err(|e| format!("XPath: {e:?}"))?
        .get_nodes_as_vec();
    if nodes.len() != 1 {
        return Err(format!("expected exactly one {expr}, got {}", nodes.len()));
    }
    Ok(nodes[0].get_content())
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

pub fn qr(ctx: &Context) -> Result<BTreeMap<u8, Vec<u8>>, String> {
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
    sdk_rounding_difference: bool,
) -> Result<(), String> {
    let doc = document(xml)?;
    let ctx = context(&doc);
    let hash = text(
        &ctx,
        "//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue",
    )?;
    if hash != expected_hash {
        return Err("invoice digest differs".into());
    }
    let cert_bytes = decode(&text(&ctx, "//ds:X509Certificate")?)?;
    if cert_bytes != expected_certificate {
        return Err("certificate differs".into());
    }
    let cert = Certificate::from_der(&cert_bytes).map_err(|e| e.to_string())?;
    let spki = cert.tbs_certificate().subject_public_key_info();
    let verifying =
        VerifyingKey::from_sec1_bytes(spki.subject_public_key.as_bytes().ok_or("unaligned key")?)
            .map_err(|e| e.to_string())?;
    let signature_bytes = decode(&text(&ctx, "//ds:SignatureValue")?)?;
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
    if text(&ctx, "//xades:CertDigest/ds:DigestValue")? != cert_digest {
        return Err("certificate digest".into());
    }
    let tags = qr(&ctx)?;
    let expected = [
        (
            1,
            text(
                &ctx,
                "//cac:AccountingSupplierParty//cac:PartyLegalEntity/cbc:RegistrationName",
            )?
            .into_bytes(),
        ),
        (
            2,
            text(
                &ctx,
                "//cac:AccountingSupplierParty//cac:PartyTaxScheme/cbc:CompanyID",
            )?
            .into_bytes(),
        ),
        (
            3,
            format!(
                "{}T{}",
                text(&ctx, "/*/cbc:IssueDate")?,
                text(&ctx, "/*/cbc:IssueTime")?
            )
            .into_bytes(),
        ),
        (
            4,
            if sdk_rounding_difference {
                b"1000.00".to_vec()
            } else {
                text(&ctx, "//cac:LegalMonetaryTotal/cbc:TaxInclusiveAmount")?.into_bytes()
            },
        ),
        (
            5,
            text(&ctx, "(/*/cac:TaxTotal/cbc:TaxAmount)[1]")?.into_bytes(),
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
    if let Some(value) = tags.get(&9) {
        if value.as_slice()
            != cert
                .signature()
                .as_bytes()
                .ok_or("unaligned cert signature")?
        {
            return Err("QR certificate signature differs".into());
        }
    }
    if text(&ctx, "/*/cbc:InvoiceTypeCode/@name")?.starts_with("02") && !tags.contains_key(&9) {
        return Err("missing simplified QR certificate signature".into());
    }
    let transforms = ctx
        .evaluate("//ds:Reference[@Id='invoiceSignedData']/ds:Transforms/ds:Transform")
        .map_err(|e| format!("{e:?}"))?
        .get_nodes_as_vec();
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
        if text(&ctx, &format!("{base}/@Algorithm"))?
            != "http://www.w3.org/TR/1999/REC-xpath-19991116"
            || text(&ctx, &format!("{base}/ds:XPath"))? != *predicate
        {
            return Err("signature exclusion transform".into());
        }
    }
    if text(
        &ctx,
        "//ds:Reference[@Id='invoiceSignedData']/ds:Transforms/ds:Transform[4]/@Algorithm",
    )? != "http://www.w3.org/2006/12/xml-c14n11"
    {
        return Err("signature canonicalization transform".into());
    }
    let time = text(&ctx, "//xades:SigningTime")?;
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
        if text(&ctx, expr)? != expected {
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
    let nodes = ctx
        .evaluate("//xades:SignedProperties")
        .map_err(|e| format!("{e:?}"))?
        .get_nodes_as_vec();
    if nodes.len() != 1 {
        return Err("SignedProperties count".into());
    }
    let mut raw = doc.node_to_string(&nodes[0]);
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
    use libxml::tree::c14n::{CanonicalizationMode, CanonicalizationOptions};
    let doc = document(xml)?;
    let ctx = context(&doc);
    let properties_hash = text(
        &ctx,
        "//ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue",
    )?;
    let bytes = properties_preimage(xml)?;
    if properties_hash
        != Base64::encode_string(format!("{:x}", Sha256::digest(bytes.as_bytes())).as_bytes())
    {
        return Err("SignedProperties digest".into());
    }
    let expected = text(
        &ctx,
        "//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue",
    )?;
    ctx.register_namespace(
        "ext",
        "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
    )
    .unwrap();
    for mut node in ctx.evaluate("//ext:UBLExtensions | //cac:Signature | //cac:AdditionalDocumentReference[cbc:ID='QR']").map_err(|e| format!("{e:?}"))?.get_nodes_as_vec() { node.unlink(); }
    let canonical = doc
        .canonicalize(
            CanonicalizationOptions {
                mode: CanonicalizationMode::Canonical1_1,
                inclusive_ns_prefixes: vec![],
                with_comments: false,
            },
            None,
        )
        .map_err(|e| format!("{e:?}"))?;
    if expected != Base64::encode_string(&Sha256::digest(canonical.as_bytes())) {
        return Err("signed content digest".into());
    }
    Ok(())
}
