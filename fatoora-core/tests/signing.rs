mod common;

use fatoora_core::config::EnvironmentType;
use fatoora_core::csr::CsrProperties;
use fatoora_core::invoice::sign::{InvoiceSigner, SigningError, invoice_hash_base64};
use fatoora_core::invoice::xml::ToXml;
use base64ct::{Base64, Encoding};
use k256::ecdsa::SigningKey;
use k256::pkcs8::EncodePrivateKey;
use libxml::parser::Parser;
use libxml::xpath;
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

const CBC_NS: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";
const CAC_NS: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";

#[test]
fn sign_invoice_emits_signature_and_qr() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_config = CsrProperties::parse_csr_config(&config_path).expect("csr config");
    let (_csr, signer_key) = csr_config
        .build_with_rng(EnvironmentType::NonProduction)
        .expect("csr build");
    let key_der = signer_key.to_pkcs8_der().expect("key der");
    let cert_der = build_test_cert(&signer_key);

    let signer = InvoiceSigner::from_der(&cert_der, key_der.as_bytes()).expect("signer");
    let signed = common::dummy_finalized_invoice()
        .sign(&signer)
        .expect("sign invoice");
    let xml = signed.to_xml().expect("signed xml");
    println!("{}", xml);
    assert!(xml.contains("ds:SignatureValue"));

    let doc = Parser::default()
        .parse_string(&xml)
        .expect("parse signed xml");
    let ctx = xpath::Context::new(&doc).expect("xpath context");
    ctx.register_namespace("cbc", CBC_NS).expect("cbc ns");
    ctx.register_namespace("cac", CAC_NS).expect("cac ns");

    let nodes = ctx
        .evaluate("//cac:AdditionalDocumentReference[cbc:ID[normalize-space(text())='QR']]/cac:Attachment/cbc:EmbeddedDocumentBinaryObject")
        .expect("qr xpath")
        .get_nodes_as_vec();
    assert!(!nodes.is_empty(), "missing QR node");
    let qr_value = nodes[0].get_content();
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
        SigningError::SigningError(msg) => {
            assert!(msg.contains("Certificate parse error"), "unexpected: {msg}");
        }
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
        SigningError::SigningError(msg) => {
            assert!(msg.contains("Private key parse error"), "unexpected: {msg}");
        }
    }
    drop(key_der);
}

#[test]
fn signer_from_pem_accepts_valid_pem() {
    let (_signer_key, key_der, cert_der) = build_test_signing_material();
    let cert_pem = pem_wrap("CERTIFICATE", &cert_der);
    let key_pem = pem_wrap("PRIVATE KEY", &key_der);
    let signer = InvoiceSigner::from_pem(&cert_pem, &key_pem).expect("valid pem signer");
    let _ = signer.certificate();
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
    let err = match signer.sign_xml("<Invoice>") {
        Ok(_) => panic!("invalid xml rejected"),
        Err(err) => err,
    };
    match err {
        SigningError::SigningError(msg) => {
            let is_parse_error = msg.contains("XML parse error");
            let is_missing = msg.contains("Missing issue date") || msg.contains("Missing");
            assert!(is_parse_error || is_missing, "unexpected: {msg}");
        }
    }
}

#[test]
fn sign_xml_emits_signature_and_signing_time() {
    let (signer, _key) = build_test_signer();
    let invoice = common::dummy_finalized_invoice();
    let unsigned_xml = invoice.to_xml().expect("unsigned xml");
    let signed_xml = signer.sign_xml(&unsigned_xml).expect("sign xml");
    assert!(signed_xml.contains("ds:SignatureValue"));

    let doc = Parser::default()
        .parse_string(&signed_xml)
        .expect("parse signed xml");
    let ctx = xpath::Context::new(&doc).expect("xpath context");
    let nodes = ctx
        .evaluate("//*[local-name()='SigningTime']")
        .expect("signing time xpath")
        .get_nodes_as_vec();
    assert!(!nodes.is_empty(), "missing SigningTime");
    let signing_time = nodes[0].get_content();
    assert_eq!(signing_time.trim(), "2024-01-01T12:30:00");
}

#[test]
fn invoice_hash_base64_decodes_to_32_bytes() {
    let invoice = common::dummy_finalized_invoice();
    let xml = invoice.to_xml().expect("unsigned xml");
    let doc = Parser::default().parse_string(&xml).expect("parse xml");
    let hash_b64 = invoice_hash_base64(&doc).expect("hash");
    let decoded = Base64::decode_vec(&hash_b64).expect("decode b64");
    assert_eq!(decoded.len(), 32);
}

fn build_test_cert(key: &SigningKey) -> Vec<u8> {
    let serial_number = SerialNumber::from(1u32);
    let validity = Validity::from_now(Duration::new(3600, 0)).expect("validity");
    let subject = Name::from_str("CN=Test,O=Fatoora,C=SA").expect("subject");
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

fn build_test_signing_material() -> (SigningKey, Vec<u8>, Vec<u8>) {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_config = CsrProperties::parse_csr_config(&config_path).expect("csr config");
    let (_csr, signer_key) = csr_config
        .build_with_rng(EnvironmentType::NonProduction)
        .expect("csr build");
    let key_der = signer_key.to_pkcs8_der().expect("key der").as_bytes().to_vec();
    let cert_der = build_test_cert(&signer_key);
    (signer_key, key_der, cert_der)
}

fn build_test_signer() -> (InvoiceSigner, SigningKey) {
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
