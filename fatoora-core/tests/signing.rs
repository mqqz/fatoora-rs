mod common;

use fatoora_core::config::EnvironmentType;
use fatoora_core::csr::CsrProperties;
use fatoora_core::invoice::sign::InvoiceSigner;
use fatoora_core::invoice::xml::ToXml;
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
