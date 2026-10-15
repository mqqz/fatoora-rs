mod common;

use base64ct::{Base64, Encoding};
use fatoora_core::config::EnvironmentType;
use fatoora_core::csr::{CsrProperties, SigningKey as CoreSigningKey};
use fatoora_core::invoice::sign::{InvoiceSigner, SigningError};
use k256::ecdsa::SigningKey as K256SigningKey;
use k256::pkcs8::DecodePrivateKey;
#[path = "support/xml.rs"]
#[allow(dead_code)]
mod test_xml;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, profile};
use x509_cert::der::Encode;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::EncodePublicKey;
use x509_cert::spki::SubjectPublicKeyInfo;
use x509_cert::time::Validity;

#[test]
fn sign_invoice_emits_signature_and_qr() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_props = std::fs::read_to_string(&config_path).expect("read csr config");
    let csr_config = CsrProperties::from_properties_str(&csr_props).expect("csr config");
    let signer_key = CoreSigningKey::generate();
    let _csr = csr_config
        .build(&signer_key, EnvironmentType::NonProduction)
        .expect("csr build");
    let key_der = signer_key.to_der().expect("key der");
    let k256_key = K256SigningKey::from_pkcs8_der(&key_der).expect("key der");
    let cert_der = build_test_cert(&k256_key);

    let signer = InvoiceSigner::from_der(&cert_der, &key_der).expect("signer");
    let signed = common::dummy_finalized_invoice()
        .sign(&signer)
        .expect("sign invoice");
    let xml = signed.xml().to_owned();
    println!("{}", xml);
    assert!(xml.contains("ds:SignatureValue"));

    let doc = roxmltree::Document::parse(&xml).unwrap();
    let qr_value = test_xml::text(&doc, "//cac:AdditionalDocumentReference[cbc:ID='QR']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject").unwrap();
    assert!(!qr_value.trim().is_empty(), "empty QR value");
}

#[test]
fn signer_from_der_rejects_invalid_cert() {
    let (signer_key, key_der, _cert_der) = build_test_signing_material();
    let err = match InvoiceSigner::from_der(b"not-der", &key_der) {
        Ok(_) => panic!("invalid cert rejected"),
        Err(err) => err,
    };
    match err {
        SigningError::InvalidInput(diagnostic) => {
            let msg = diagnostic.message();
            assert!(msg.contains("Certificate parse error"), "unexpected: {msg}");
        }
        other => panic!("expected invalid input: {other}"),
    }
    drop(signer_key);
}

#[test]
fn signer_from_der_rejects_invalid_key() {
    let (_signer_key, key_der, cert_der) = build_test_signing_material();
    let err = match InvoiceSigner::from_der(&cert_der, b"not-der") {
        Ok(_) => panic!("invalid key rejected"),
        Err(err) => err,
    };
    match err {
        SigningError::InvalidInput(diagnostic) => {
            let msg = diagnostic.message();
            assert!(msg.contains("Private key parse error"), "unexpected: {msg}");
        }
        other => panic!("expected invalid input: {other}"),
    }
    drop(key_der);
}

#[test]
fn signer_from_pem_accepts_valid_pem() {
    let (_signer_key, key_der, cert_der) = build_test_signing_material();
    let cert_pem = pem_wrap("CERTIFICATE", &cert_der);
    let key_pem = pem_wrap("PRIVATE KEY", &key_der);
    let signer = InvoiceSigner::from_pem(&cert_pem, &key_pem).expect("valid pem signer");
    assert_eq!(signer.certificate_der().unwrap(), cert_der);
    assert_eq!(signer.certificate_pem().unwrap(), cert_pem);
}

#[test]
fn signer_from_pem_rejects_invalid_cert() {
    let (_signer_key, key_der, _cert_der) = build_test_signing_material();
    let bad_cert_pem = "-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----\n";
    let key_pem = pem_wrap("PRIVATE KEY", &key_der);
    assert!(InvoiceSigner::from_pem(bad_cert_pem, &key_pem).is_err());
}

#[test]
fn sign_xml_rejects_invalid_xml() {
    let (signer, _key) = build_test_signer();
    let err = match signer.sign_xml("") {
        Ok(_) => panic!("invalid xml rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(err, SigningError::Xml(_)),
        "expected XML failure: {err}"
    );
    assert_eq!(err.kind(), fatoora_core::ErrorKind::Xml);
}

#[test]
fn sign_xml_emits_signature_and_signing_time() {
    let (signer, _key) = build_test_signer();
    let invoice = common::dummy_finalized_invoice();
    let unsigned_xml = invoice.to_xml().expect("unsigned xml");
    let signed_xml: String = signer.sign_xml(&unsigned_xml).expect("sign xml");
    assert!(signed_xml.contains("ds:SignatureValue"));

    let doc = roxmltree::Document::parse(&signed_xml).unwrap();
    let signing_time = test_xml::text(&doc, "//xades:SigningTime").unwrap();
    assert_eq!(signing_time.trim(), "2024-01-01T12:30:00");
}

#[test]
fn invoice_hash_base64_decodes_to_32_bytes() {
    let invoice = common::dummy_finalized_invoice();
    let hash_b64 = invoice.hash_base64().expect("hash");
    let decoded = Base64::decode_vec(&hash_b64).expect("decode b64");
    assert_eq!(decoded.len(), 32);
}

#[test]
fn signed_invoice_hash_base64_matches_finalized_invoice() {
    let (signer, _key) = build_test_signer();
    let invoice = common::dummy_finalized_invoice();
    let expected = invoice.hash_base64().expect("hash");
    let signed = invoice.sign(&signer).expect("sign invoice");
    let actual = signed.hash_base64().expect("hash");
    assert_eq!(expected, actual);
}

fn build_test_cert(key: &K256SigningKey) -> Vec<u8> {
    build_test_cert_named(key, 1, "CN=Test,O=Fatoora,C=SA")
}
fn build_test_cert_named(key: &K256SigningKey, serial: u32, name: &str) -> Vec<u8> {
    let serial_number = SerialNumber::from(serial);
    let validity = Validity::from_now(Duration::new(3600, 0)).expect("validity");
    let subject = Name::from_str(name).expect("subject");
    let profile = profile::cabf::Root::new(false, subject).expect("profile");
    let public_key = key.verifying_key();
    let spki_der = public_key.to_public_key_der().expect("public key der");
    let pub_key = SubjectPublicKeyInfo::try_from(spki_der.as_bytes()).expect("spki");
    let builder =
        CertificateBuilder::new(profile, serial_number, validity, pub_key).expect("builder");
    let cert = builder
        .build::<_, k256::ecdsa::DerSignature>(key)
        .expect("certificate");
    cert.to_der().expect("cert der")
}

fn build_test_signing_material() -> (CoreSigningKey, Vec<u8>, Vec<u8>) {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_props = std::fs::read_to_string(&config_path).expect("read csr config");
    let csr_config = CsrProperties::from_properties_str(&csr_props).expect("csr config");
    let signer_key = CoreSigningKey::generate();
    let _csr = csr_config
        .build(&signer_key, EnvironmentType::NonProduction)
        .expect("csr build");
    let key_der = signer_key.to_der().expect("key der");
    let k256_key = K256SigningKey::from_pkcs8_der(&key_der).expect("key der");
    let cert_der = build_test_cert(&k256_key);
    (signer_key, key_der, cert_der)
}

fn build_test_signer() -> (InvoiceSigner, CoreSigningKey) {
    let (signer_key, key_der, cert_der) = build_test_signing_material();
    let signer = InvoiceSigner::from_der(&cert_der, &key_der).expect("signer");
    (signer, signer_key)
}

fn pem_wrap(label: &str, der: &[u8]) -> String {
    let b64 = Base64::encode_string(der);
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 chunk"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

#[test]
fn non_byte_aligned_certificate_signature_returns_an_input_error() {
    use x509_cert::Certificate;
    use x509_cert::der::Decode;

    let (_, key_der, mut cert_der) = build_test_signing_material();
    let certificate = Certificate::from_der(&cert_der).unwrap();
    let signature_len = certificate.signature().as_bytes().unwrap().len();
    // Certificate's last field is a BIT STRING. Keep the DER lengths unchanged
    // but set one unused bit, producing valid ASN.1 that is not a byte string.
    let unused_bits_offset = cert_der.len() - signature_len - 1;
    assert_eq!(cert_der[unused_bits_offset], 0);
    cert_der[unused_bits_offset] = 1;
    *cert_der.last_mut().unwrap() &= 0xfe;
    let certificate = Certificate::from_der(&cert_der).unwrap();
    assert!(certificate.signature().as_bytes().is_none());

    let signer = InvoiceSigner::from_der(&cert_der, &key_der).unwrap();
    let error = common::dummy_finalized_invoice().sign(&signer).unwrap_err();
    assert_eq!(error.kind(), fatoora_core::ErrorKind::InvalidInput);
}

#[test]
fn into_xml_preserves_newly_signed_output() {
    let (signer, _) = build_test_signer();
    let signed = common::dummy_finalized_invoice().sign(&signer).unwrap();
    let expected = signed.xml().to_owned();
    let ptr = signed.xml().as_ptr();
    let owned = signed.into_xml();
    assert_eq!(owned, expected);
    assert_eq!(owned.as_ptr(), ptr);
}

#[test]
fn malformed_signing_timestamps_fail_without_poisoning_the_signer() {
    let (signer, _) = build_test_signer();
    let unsigned = common::dummy_finalized_invoice().to_xml().unwrap();
    for (from, to, label) in [
        ("2024-01-01", "2024-02-30", "issue date"),
        ("12:30:00", "25:30:00", "issue time"),
    ] {
        assert!(unsigned.contains(from));
        let error = signer
            .sign_xml(&unsigned.replacen(from, to, 1))
            .unwrap_err();
        assert_eq!(error.kind(), fatoora_core::ErrorKind::InvalidInput);
        assert!(error.to_string().contains(label));
        let details: serde_json::Value =
            serde_json::from_str(&fatoora_core::Error::from(error).details_json()).unwrap();
        assert_eq!(details["type"], "signing_input");
    }
    let signed = signer.sign_xml(&unsigned).unwrap();
    let malformed = signed.replace(
        "<xades:SigningTime>2024-01-01T12:30:00</xades:SigningTime>",
        "<xades:SigningTime>invalid</xades:SigningTime>",
    );
    assert_ne!(signed, malformed);
    let error = signer.sign_xml(&malformed).unwrap_err();
    assert_eq!(error.kind(), fatoora_core::ErrorKind::InvalidInput);
    // Explicit invalid signing time must not silently fall back to issue time.
    assert!(error.to_string().contains("Invalid signing time"));
    assert!(signer.sign_xml(&unsigned).is_ok());
}

#[test]
fn pem_signer_rejects_invalid_key_after_accepting_certificate() {
    let (_, _, cert_der) = build_test_signing_material();
    let error = InvoiceSigner::from_pem(&pem_wrap("CERTIFICATE", &cert_der), "invalid key")
        .err()
        .unwrap();
    assert_eq!(error.kind(), fatoora_core::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("Private key parse error"));
}

#[test]
fn signing_qr_overflow_preserves_error_details_and_signer_reusability() {
    use fatoora_core::invoice::QrCodeError;
    let (signer, _) = build_test_signer();
    let xml = common::dummy_finalized_invoice().to_xml().unwrap();
    // Arabic characters occupy two UTF-8 bytes: this is 256 bytes, not 128.
    let oversized = xml.replace("Acme Inc", &"ش".repeat(128));
    assert_ne!(oversized, xml);
    let error = signer.sign_xml(&oversized).unwrap_err();
    assert!(matches!(
        error,
        SigningError::Qr(QrCodeError::ValueTooLong { tag: 1, len: 256 })
    ));
    assert_eq!(error.kind(), fatoora_core::ErrorKind::InvalidInput);
    let signed = signer.sign_xml(&xml).unwrap();
    let parsed = fatoora_core::invoice::xml::parse::parse_signed_invoice_xml(&signed).unwrap();
    assert_eq!(
        parsed.hash_base64().unwrap(),
        common::dummy_finalized_invoice().hash_base64().unwrap()
    );
}

#[test]
fn hashing_rejects_relative_namespace_uris() {
    use fatoora_core::invoice::sign::invoice_hash_base64_from_xml_str;
    // Well-formed XML can still be impossible to canonicalize. Returning a hash
    // of an empty or partial canonicalization would sign different content.
    let error = invoice_hash_base64_from_xml_str(
        "<Invoice xmlns=\"relative\"><Amount>100</Amount></Invoice>",
    )
    .unwrap_err();
    assert!(matches!(error, SigningError::Xml(_)));
    assert_eq!(error.kind(), fatoora_core::ErrorKind::Xml);
}

#[test]
fn malformed_closing_tag_is_rejected_without_poisoning_the_signer() {
    let input = include_str!("fixtures/malformed/closing-tag.xml");
    let (signer, _) = build_test_signer();
    assert!(signer.sign_xml(input).is_err());
    assert!(fatoora_core::invoice::sign::invoice_hash_base64_from_xml_str(input).is_err());
    assert!(
        signer
            .sign_xml(&common::dummy_finalized_invoice().to_xml().unwrap())
            .is_ok()
    );
}

#[test]
fn repeated_signing_preserves_bytes_and_unrelated_extension_trivia() {
    let (signer, _) = build_test_signer();
    let xml = common::dummy_finalized_invoice().to_xml().unwrap();
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let supplier = doc
        .root_element()
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "AccountingSupplierParty")
        .unwrap();
    let at = supplier.range().start;
    let mut input = xml.clone();
    let trivia = "\r\n<!-- supplier --><?preserve yes?>\r\n";
    input.insert_str(at, trivia);
    let signed = signer.sign_xml(&input).unwrap();
    assert!(signed.contains(trivia));
    assert_eq!(signer.sign_xml(&signed).unwrap(), signed);
    let hash_target = signed.replace("Target=\"signature\"", "Target=\"#signature\"");
    assert_ne!(hash_target, signed);
    assert_eq!(signer.sign_xml(&hash_target).unwrap(), signed);
    assert_eq!(
        fatoora_core::invoice::sign::invoice_hash_base64_from_xml_str(&signed).unwrap(),
        fatoora_core::invoice::sign::invoice_hash_base64_from_xml_str(&input).unwrap()
    );
}

#[test]
fn resigning_rejects_other_certificates_and_incomplete_owned_material() {
    let (signer, _) = build_test_signer();
    let (other, _) = build_test_signer();
    let input = common::dummy_finalized_invoice().to_xml().unwrap();
    let signed = signer.sign_xml(&input).unwrap();
    assert!(
        other
            .sign_xml(&signed)
            .unwrap_err()
            .to_string()
            .contains("different certificate")
    );
    let cert = Base64::encode_string(&signer.certificate_der().unwrap());
    for value in ["", "malformed"] {
        let partial = signed.replace(&cert, value);
        assert_eq!(
            signer.sign_xml(&partial).unwrap_err().kind(),
            fatoora_core::ErrorKind::InvalidInput
        );
    }
    let external = input.replace(
        "</Invoice>",
        "<ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#' Id='external'/></Invoice>",
    );
    assert_ne!(external, input);
    assert!(
        signer
            .sign_xml(&external)
            .unwrap_err()
            .to_string()
            .contains("externally owned")
    );
    assert_eq!(signer.sign_xml(&signed).unwrap(), signed);
}

#[test]
fn signing_rejects_a_private_key_that_does_not_match_the_certificate() {
    let (_, _, cert) = build_test_signing_material();
    let (_, other_key, _) = build_test_signing_material();
    let signer = InvoiceSigner::from_der(&cert, &other_key).unwrap();
    let input = common::dummy_finalized_invoice().to_xml().unwrap();
    assert!(
        signer
            .sign_xml(&input)
            .unwrap_err()
            .to_string()
            .contains("does not match")
    );
}

#[test]
fn renewal_using_the_same_key_requires_a_separate_unsigned_invoice() {
    let (_, key_der, certificate) = build_test_signing_material();
    let key = K256SigningKey::from_pkcs8_der(&key_der).unwrap();
    let renewed = build_test_cert_named(&key, 2, "CN=Test,O=Fatoora,C=SA");
    let old = InvoiceSigner::from_der(&certificate, &key_der).unwrap();
    let new = InvoiceSigner::from_der(&renewed, &key_der).unwrap();
    let input = common::dummy_finalized_invoice().to_xml().unwrap();
    let signed = old.sign_xml(&input).unwrap();
    assert!(
        new.sign_xml(&signed)
            .unwrap_err()
            .to_string()
            .contains("different certificate")
    );
    assert!(new.sign_xml(&input).is_ok());
}

#[test]
fn certificate_issuer_text_is_escaped_without_changing_its_preimage() {
    let (_, key_der, _) = build_test_signing_material();
    let key = K256SigningKey::from_pkcs8_der(&key_der).unwrap();
    for name in [
        "CN=Test & O'Brien,O=Fatoora,C=SA",
        r"CN=Test \> \< & O'Brien,O=Fatoora,C=SA",
    ] {
        let certificate = build_test_cert_named(&key, 3, name);
        let signer = InvoiceSigner::from_der(&certificate, &key_der).unwrap();
        let signed = signer
            .sign_xml(&common::dummy_finalized_invoice().to_xml().unwrap())
            .unwrap();
        assert!(signed.contains("&amp; O'Brien"));
        if name.contains('>') {
            assert!(signed.contains("&gt;"));
            assert!(signed.contains("&lt;"));
        }
        assert_eq!(signer.sign_xml(&signed).unwrap(), signed);
    }
}

#[test]
fn signing_preserves_unrelated_extensions_and_empty_wrapper_namespace_aliases() {
    let (signer, _) = build_test_signer();
    let xml = common::dummy_finalized_invoice().to_xml().unwrap();
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let at = doc
        .root_element()
        .children()
        .find(roxmltree::Node::is_element)
        .unwrap()
        .range()
        .start;
    let unrelated = "<ext:UBLExtension><ext:ExtensionURI>urn:example:unrelated</ext:ExtensionURI><ext:ExtensionContent><!--keep--><data xmlns='urn:example'>a&amp;b</data></ext:ExtensionContent></ext:UBLExtension>";
    for replacement in [
        format!(r#"<ext:UBLExtensions xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">{unrelated}</ext:UBLExtensions>"#),
        "<alias:UBLExtensions xmlns:alias='urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2'/>".to_string(),
    ] {
        let mut input = xml.clone();
        input.insert_str(at, &replacement);
        let signed = signer.sign_xml(&input).unwrap();
        if replacement.contains(unrelated) { assert!(signed.contains(unrelated)); }
        if replacement.starts_with("<alias:") { assert!(signed.contains("</alias:UBLExtensions>")); }
        assert_eq!(signer.sign_xml(&signed).unwrap(), signed);
    }
}

#[test]
fn signing_normalizes_qr_scalars_and_preserves_free_text() {
    let (signer, _) = build_test_signer();
    let input = common::dummy_finalized_invoice().to_xml().unwrap();
    for encoding in 0..3 {
        let doc = roxmltree::Document::parse(&input).unwrap();
        let fields = [
            "CompanyID",
            "IssueDate",
            "IssueTime",
            "TaxInclusiveAmount",
            "TaxAmount",
            "RegistrationName",
        ];
        let ranges: Vec<_> = doc
            .descendants()
            .filter(|n| {
                n.is_element()
                    && n.tag_name().namespace()
                        == Some(
                            "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                        )
                    && fields.contains(&n.tag_name().name())
            })
            .map(|n| n.range())
            .collect();
        let mut padded = input.clone();
        for range in ranges.into_iter().rev() {
            let element = &input[range.clone()];
            let start = range.start + element.find('>').unwrap() + 1;
            let end = range.start + element.rfind('<').unwrap();
            let content = &input[start..end];
            let encoded = match encoding {
                0 => format!(" {content} "),
                1 => format!("<![CDATA[ {content} ]]>"),
                _ => format!("&#32;{content}&#32;"),
            };
            padded.replace_range(start..end, &encoded);
        }
        let signed = signer.sign_xml(&padded).unwrap();
        assert_eq!(signer.sign_xml(&signed).unwrap(), signed);
        let source = roxmltree::Document::parse(&padded).unwrap();
        for field in ["RegistrationName", "TaxInclusiveAmount"] {
            let node = source
                .descendants()
                .find(|n| {
                    n.has_tag_name((
                        "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                        field,
                    ))
                })
                .unwrap();
            assert!(signed.contains(&padded[node.range()]));
        }
        let doc = roxmltree::Document::parse(&signed).unwrap();
        let qr = doc
            .descendants()
            .find(|n| {
                n.has_tag_name((
                    "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                    "AdditionalDocumentReference",
                )) && n.children().any(|c| {
                    c.has_tag_name((
                        "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                        "ID",
                    )) && c.text() == Some("QR")
                })
            })
            .unwrap();
        let encoded = qr
            .descendants()
            .find(|n| {
                n.has_tag_name((
                    "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                    "EmbeddedDocumentBinaryObject",
                ))
            })
            .unwrap()
            .text()
            .unwrap();
        let bytes = Base64::decode_vec(encoded).unwrap();
        let mut tags = std::collections::BTreeMap::new();
        let mut cursor = bytes.as_slice();
        while !cursor.is_empty() {
            let (tag, len) = (cursor[0], usize::from(cursor[1]));
            tags.insert(tag, cursor[2..2 + len].to_vec());
            cursor = &cursor[2 + len..];
        }
        for (tag, expected) in [
            (1, " Acme Inc "),
            (2, "399999999900003"),
            (3, "2024-01-01T12:30:00"),
            (4, "115.00"),
            (5, "15.00"),
        ] {
            assert_eq!(tags[&tag], expected.as_bytes(), "QR tag {tag}");
        }
    }
}

#[test]
fn signing_rejects_output_that_exceeds_the_complete_document_limit() {
    let (signer, _) = build_test_signer();
    let mut input = common::dummy_finalized_invoice().to_xml().unwrap();
    let target = 8 * 1024 * 1024 - 256;
    let at = input.find("<cac:AccountingSupplierParty>").unwrap();
    let comment = format!("<!--{}-->", "x".repeat(target - input.len() - 7));
    input.insert_str(at, &comment);
    assert_eq!(input.len(), target);
    let error = signer.sign_xml(&input).unwrap_err();
    assert!(error.to_string().contains("document byte limit"), "{error}");
    assert!(
        signer
            .sign_xml(&common::dummy_finalized_invoice().to_xml().unwrap())
            .is_ok()
    );
}

#[test]
fn signing_qr_preserves_certificate_spki_point_encoding() {
    let (_, key_der, _) = build_test_signing_material();
    let key = K256SigningKey::from_pkcs8_der(&key_der).unwrap();
    for compressed in [true, false] {
        let point = key.verifying_key().to_sec1_point(compressed);
        let point = point.as_bytes();
        // id-ecPublicKey + secp256k1, followed by the original SEC1 point.
        let mut spki = vec![
            0x30,
            (point.len() + 21) as u8,
            0x30,
            0x10,
            0x06,
            0x07,
            0x2a,
            0x86,
            0x48,
            0xce,
            0x3d,
            0x02,
            0x01,
            0x06,
            0x05,
            0x2b,
            0x81,
            0x04,
            0x00,
            0x0a,
            0x03,
            (point.len() + 1) as u8,
            0,
        ];
        spki.extend_from_slice(point);
        let public = SubjectPublicKeyInfo::try_from(spki.as_slice()).unwrap();
        let subject = Name::from_str("CN=Point encoding,O=Fatoora,C=SA").unwrap();
        let profile = profile::cabf::Root::new(false, subject).unwrap();
        let certificate = CertificateBuilder::new(
            profile,
            SerialNumber::from(5u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            public,
        )
        .unwrap()
        .build::<_, k256::ecdsa::DerSignature>(&key)
        .unwrap()
        .to_der()
        .unwrap();
        let signer = InvoiceSigner::from_der(&certificate, &key_der).unwrap();
        let signed = signer
            .sign_xml(&common::dummy_finalized_invoice().to_xml().unwrap())
            .unwrap();
        assert_eq!(signer.sign_xml(&signed).unwrap(), signed);
        let doc = roxmltree::Document::parse(&signed).unwrap();
        let qr = doc
            .descendants()
            .find(|n| {
                n.has_tag_name((
                    "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                    "EmbeddedDocumentBinaryObject",
                )) && n.ancestors().any(|a| {
                    a.children().any(|c| {
                        c.has_tag_name((
                            "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                            "ID",
                        )) && c.text() == Some("QR")
                    })
                })
            })
            .unwrap()
            .text()
            .unwrap();
        let bytes = Base64::decode_vec(qr).unwrap();
        let mut cursor = bytes.as_slice();
        while cursor[0] != 8 {
            cursor = &cursor[2 + usize::from(cursor[1])..];
        }
        assert_eq!(&cursor[2..2 + usize::from(cursor[1])], spki.as_slice());
    }
}

#[test]
fn signing_document_limits_apply_before_parsing_and_after_generation() {
    let (_, key, certificate) = build_test_signing_material();
    let signer = InvoiceSigner::from_der(&certificate, &key).unwrap();
    let limit = 8 * 1024 * 1024;
    use fatoora_core::invoice::{
        InvoiceBuilder, InvoiceNote, InvoiceSubType, InvoiceType, VatCategory,
    };
    let sample = common::dummy_finalized_invoice();
    let typed = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified))
        .id("INV-LARGE")
        .uuid("8e6000cf-1a98-4174-b3e7-b5d5954bc10d")
        .issue_datetime("2024-01-01T12:30:00Z")
        .currency("SAR")
        .previous_invoice_hash("hash")
        .invoice_counter(0)
        .seller(sample.data().seller().clone())
        .payment_means_code("10")
        .vat_category(VatCategory::Standard)
        .line_item(sample.data().line_items()[0].clone())
        .note(InvoiceNote::new("en", "x".repeat(limit)))
        .build()
        .unwrap();
    assert!(
        typed
            .to_xml()
            .unwrap_err()
            .to_string()
            .contains("XML output exceeds document byte limit")
    );
    let error = typed.sign(&signer).unwrap_err().to_string();
    assert!(
        error.contains("XML output exceeds document byte limit"),
        "{error}"
    );
    assert!(!error.contains("XML parse error"));

    // Invalid XML proves the byte boundary is checked before parser diagnostics.
    let oversized = "!".repeat(limit + 1);
    assert!(
        signer
            .sign_xml(&oversized)
            .unwrap_err()
            .to_string()
            .contains("XML input bytes")
    );
    let xml = common::dummy_finalized_invoice().to_xml().unwrap();
    let signed_size = signer.sign_xml(&xml).unwrap().len();
    let remaining = limit - signed_size + 256 - "<!---->".len();
    let near_limit = xml.replacen(
        "</Invoice>",
        &format!("<!--{}--></Invoice>", "x".repeat(remaining)),
        1,
    );
    assert!(near_limit.len() < limit);
    let error = signer.sign_xml(&near_limit).unwrap_err().to_string();
    assert!(error.contains("document byte limit"), "{error}");
    assert!(signer.sign_xml(&xml).is_ok());
}

#[test]
fn builder_qr_accessor_matches_embedded_qr_with_padded_seller_name() {
    let (_, key, certificate) = build_test_signing_material();
    let signer = InvoiceSigner::from_der(&certificate, &key).unwrap();
    for name in [" Acme Inc ", "Acme\rCorp", "Acme\r\nCorp", "Acme\nCorp"] {
        let invoice = common::dummy_finalized_invoice_with_seller_name(name);
        let signed = invoice.sign(&signer).unwrap();
        let document = roxmltree::Document::parse(signed.xml()).unwrap();
        let reference = document
            .descendants()
            .find(|node| {
                node.has_tag_name((
                    "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                    "AdditionalDocumentReference",
                )) && node.children().any(|child| {
                    child.has_tag_name((
                        "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                        "ID",
                    )) && child.text() == Some("QR")
                })
            })
            .unwrap();
        let embedded = reference
            .descendants()
            .find(|node| {
                node.has_tag_name((
                    "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                    "EmbeddedDocumentBinaryObject",
                ))
            })
            .unwrap()
            .text()
            .unwrap();
        assert_eq!(signed.qr_code(), embedded);
        let bytes = Base64::decode_vec(signed.qr_code()).unwrap();
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[2..2 + usize::from(bytes[1])], name.as_bytes());
    }
}

#[test]
fn resigning_rejects_changed_owned_reference_bindings() {
    let (signer, _) = build_test_signer();
    let input = common::dummy_finalized_invoice().to_xml().unwrap();
    let signed = signer.sign_xml(&input).unwrap();
    for (old, replacement) in [
        ("Target=\"signature\"", "Target=\"external\""),
        ("Id=\"xadesSignedProperties\"", "Id=\"external\""),
        ("Id=\"invoiceSignedData\"", "Id=\"external\""),
        ("URI=\"#xadesSignedProperties\"", "URI=\"#external\""),
    ] {
        assert_eq!(signed.matches(old).count(), 1);
        let changed = signed.replace(old, replacement);
        assert_eq!(
            signer.sign_xml(&changed).unwrap_err().kind(),
            fatoora_core::ErrorKind::InvalidInput
        );
    }
    assert_eq!(signer.sign_xml(&signed).unwrap(), signed);
}

#[test]
fn signing_preserves_whitespace_padded_qr_references() {
    let (signer, _) = build_test_signer();
    let mut input = common::dummy_finalized_invoice().to_xml().unwrap();
    let at = input.find("<cac:AccountingSupplierParty>").unwrap();
    let reference = "<cac:AdditionalDocumentReference><cbc:ID> QR </cbc:ID><cac:Attachment><cbc:EmbeddedDocumentBinaryObject mimeCode='text/plain'>KEEP</cbc:EmbeddedDocumentBinaryObject></cac:Attachment></cac:AdditionalDocumentReference>";
    input.insert_str(at, reference);
    let signed = signer.sign_xml(&input).unwrap();
    assert!(signed.contains(reference));
    let doc = roxmltree::Document::parse(&signed).unwrap();
    let ids: Vec<_> = doc
        .root_element()
        .children()
        .filter(|n| {
            n.has_tag_name((
                "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                "AdditionalDocumentReference",
            ))
        })
        .flat_map(|n| n.children())
        .filter(|n| {
            n.has_tag_name((
                "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                "ID",
            ))
        })
        .filter_map(|n| n.text())
        .collect();
    assert_eq!(ids.iter().filter(|&&id| id == "QR").count(), 1);
    assert_eq!(ids.iter().filter(|&&id| id == " QR ").count(), 1);
    assert_eq!(signer.sign_xml(&signed).unwrap(), signed);
}
