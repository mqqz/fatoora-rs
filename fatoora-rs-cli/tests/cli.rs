use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use fatoora_core::invoice::sign::invoice_hash_base64;
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml_file;
use k256::ecdsa::SigningKey;
use k256::pkcs8::EncodePrivateKey;
use libxml::parser::Parser as XmlParser;
use x509_cert::builder::{Builder, CertificateBuilder, profile};
use x509_cert::der::EncodePem;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{EncodePublicKey, SubjectPublicKeyInfo};
use x509_cert::time::Validity;

fn cli_exe() -> &'static str {
    env!("CARGO_BIN_EXE_fatoora-rs-cli")
}

fn csr_config_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fatoora-core")
        .join("tests")
        .join("fixtures")
        .join("csr-configs")
        .join("csr-config-example-EN.properties")
}

fn signed_invoice_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fatoora-core")
        .join("tests")
        .join("fixtures")
        .join("invoices")
        .join("sample-simplified-invoice.xml")
}

fn xsd_invoice_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fatoora-core")
        .join("assets")
        .join("schemas")
        .join("UBL2.1")
        .join("xsd")
        .join("maindoc")
        .join("UBL-Invoice-2.1.xsd")
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("{prefix}-{nonce}"));
    path
}

fn build_test_cert_pem(key: &SigningKey) -> String {
    let serial_number = SerialNumber::from(1u32);
    let validity = Validity::from_now(std::time::Duration::new(3600, 0)).expect("validity");
    let subject = Name::from_str("CN=Test,O=Fatoora,C=SA").expect("subject");
    let profile = profile::cabf::Root::new(false, subject).expect("profile");
    let public_key = key.verifying_key();
    let spki_der = public_key.to_public_key_der().expect("public key der");
    let pub_key = SubjectPublicKeyInfo::try_from(spki_der.as_bytes()).expect("spki");
    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("builder");
    let cert = builder
        .build::<_, k256::ecdsa::DerSignature>(key)
        .expect("certificate");
    cert.to_pem(Default::default()).expect("cert pem")
}

#[test]
fn csr_command_writes_outputs() {
    let csr_path = unique_temp_path("csr");
    let key_path = unique_temp_path("key");
    let output = Command::new(cli_exe())
        .args([
            "csr",
            "--csr-config",
            csr_config_fixture().to_str().unwrap(),
            "--generated-csr",
            csr_path.to_str().unwrap(),
            "--private-key",
            key_path.to_str().unwrap(),
            "--pem",
        ])
        .output()
        .expect("run csr command");

    assert!(
        output.status.success(),
        "csr command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(csr_path.exists(), "CSR output not written");
    assert!(key_path.exists(), "key output not written");

    let csr_contents = std::fs::read_to_string(&csr_path).expect("read csr");
    let key_contents = std::fs::read_to_string(&key_path).expect("read key");
    assert!(!csr_contents.trim().is_empty());
    assert!(!key_contents.trim().is_empty());

    let _ = std::fs::remove_file(csr_path);
    let _ = std::fs::remove_file(key_path);
}

#[test]
fn validate_command_reports_ok() {
    let fixture = signed_invoice_fixture();
    let output = Command::new(cli_exe())
        .args([
            "validate",
            "--invoice",
            fixture.to_str().unwrap(),
            "--xsd-path",
            xsd_invoice_path().to_str().unwrap(),
        ])
        .output()
        .expect("run validate command");

    assert!(
        output.status.success(),
        "validate command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("OK"));
}

#[test]
fn sign_command_outputs_signed_invoice() {
    let fixture = signed_invoice_fixture();
    let key = SigningKey::generate();
    let key_pem = key
        .to_pkcs8_pem(k256::pkcs8::LineEnding::LF)
        .expect("key pem")
        .to_string();
    let cert_pem = build_test_cert_pem(&key);

    let key_path = unique_temp_path("sign-key");
    let cert_path = unique_temp_path("sign-cert");
    let signed_path = unique_temp_path("signed-invoice");
    std::fs::write(&key_path, key_pem.as_bytes()).expect("write key");
    std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert");

    let output = Command::new(cli_exe())
        .args([
            "sign",
            "--invoice",
            fixture.to_str().unwrap(),
            "--cert",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--signed-invoice",
            signed_path.to_str().unwrap(),
        ])
        .output()
        .expect("run sign command");

    assert!(
        output.status.success(),
        "sign command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed_xml = std::fs::read_to_string(&signed_path).expect("read signed invoice");
    assert!(signed_xml.contains("<ds:Signature"));

    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(signed_path);
}

#[test]
fn qr_command_outputs_payload() {
    let fixture = signed_invoice_fixture();
    let output = Command::new(cli_exe())
        .args(["qr", "--invoice"])
        .arg(&fixture)
        .output()
        .expect("run qr command");

    assert!(
        output.status.success(),
        "qr command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = String::from_utf8_lossy(&output.stdout);
    assert!(
        !payload.trim().is_empty(),
        "expected non-empty QR payload"
    );
}

#[test]
fn generate_hash_outputs_expected() {
    let fixture = signed_invoice_fixture();
    let xml = std::fs::read_to_string(&fixture).expect("read fixture");
    let doc = XmlParser::default()
        .parse_string(&xml)
        .expect("parse fixture XML");
    let expected = invoice_hash_base64(&doc).expect("compute hash");

    let output = Command::new(cli_exe())
        .args(["generate-hash", "--invoice"])
        .arg(&fixture)
        .output()
        .expect("run generate-hash command");

    assert!(
        output.status.success(),
        "generate-hash failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8_lossy(&output.stdout);
    assert_eq!(actual.trim(), expected);
}

#[test]
fn invoice_request_emits_json_payload() {
    let fixture = signed_invoice_fixture();
    let signed = parse_signed_invoice_xml_file(&fixture).expect("parse signed invoice");

    let output = Command::new(cli_exe())
        .args(["invoice-request", "--invoice"])
        .arg(&fixture)
        .output()
        .expect("run invoice-request command");

    assert!(
        output.status.success(),
        "invoice-request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .expect("parse json output");
    assert_eq!(
        payload.get("invoiceHash").and_then(|v| v.as_str()),
        Some(signed.invoice_hash())
    );
    assert_eq!(
        payload.get("uuid").and_then(|v| v.as_str()),
        Some(signed.uuid())
    );
    let expected_invoice = signed.to_xml_base64();
    assert_eq!(
        payload.get("invoice").and_then(|v| v.as_str()),
        Some(expected_invoice.as_str())
    );
}
