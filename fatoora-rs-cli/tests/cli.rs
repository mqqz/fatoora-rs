use base64ct::{Base64, Encoding};
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;
use std::path::PathBuf;
use std::process::Command;

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

fn finalized_invoice_without_qr_fixture() -> PathBuf {
    let signed_xml =
        std::fs::read_to_string(signed_invoice_fixture()).expect("read signed fixture");
    let finalized_xml = strip_qr_reference(&signed_xml);
    let output = unique_temp_path("finalized-no-qr");
    std::fs::write(&output, finalized_xml.as_bytes()).expect("write finalized fixture");
    output
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

fn strip_qr_reference(xml: &str) -> String {
    let marker = "<cbc:ID>QR</cbc:ID>";
    let qr_index = xml.find(marker).expect("QR marker in fixture");
    let start = xml[..qr_index]
        .rfind("<cac:AdditionalDocumentReference>")
        .expect("start of QR additional document reference");
    let end_tag = "</cac:AdditionalDocumentReference>";
    let end = xml[qr_index..]
        .find(end_tag)
        .map(|offset| qr_index + offset + end_tag.len())
        .expect("end of QR additional document reference");
    let mut output = String::with_capacity(xml.len());
    output.push_str(&xml[..start]);
    output.push_str(&xml[end..]);
    output
}

fn decode_tlv(payload_b64: &str) -> Vec<(u8, Vec<u8>)> {
    let bytes = Base64::decode_vec(payload_b64.trim()).expect("decode qr base64");
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let tag = bytes[i];
        let len = bytes[i + 1] as usize;
        i += 2;
        let end = i + len;
        assert!(end <= bytes.len(), "invalid TLV length");
        out.push((tag, bytes[i..end].to_vec()));
        i = end;
    }
    assert_eq!(i, bytes.len(), "trailing bytes in TLV payload");
    out
}

fn cert_fixture_base64() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fatoora-core")
        .join("tests")
        .join("fixtures")
        .join("certs")
        .join("zatca_cert_b64.txt")
}

fn key_fixture_der() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fatoora-core")
        .join("tests")
        .join("fixtures")
        .join("pkeys")
        .join("test_zatca_pkey.der")
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
        .args(["validate", "--invoice", fixture.to_str().unwrap()])
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
    let key_path = unique_temp_path("sign-key");
    let cert_path = unique_temp_path("sign-cert");
    let signed_path = unique_temp_path("signed-invoice");
    let cert_b64 = std::fs::read_to_string(cert_fixture_base64()).expect("read cert b64");
    let inner_b64 = Base64::decode_vec(cert_b64.trim()).expect("decode cert wrapper");
    let inner_b64_str = std::str::from_utf8(&inner_b64).expect("decode cert inner b64");
    let cert_der = Base64::decode_vec(inner_b64_str.trim()).expect("decode cert der");
    let key_der = std::fs::read(key_fixture_der()).expect("read key der");
    std::fs::write(&key_path, &key_der).expect("write key");
    std::fs::write(&cert_path, &cert_der).expect("write cert");

    let output = Command::new(cli_exe())
        .args([
            "sign",
            "--invoice",
            fixture.to_str().unwrap(),
            "--cert",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--cert-format",
            "der",
            "--key-format",
            "der",
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
fn qr_command_generates_payload_for_signed_invoice() {
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
    assert!(!payload.trim().is_empty(), "expected non-empty QR payload");

    let read_output = Command::new(cli_exe())
        .args(["qr-read", "--invoice"])
        .arg(&fixture)
        .output()
        .expect("run qr-read command");
    assert!(
        read_output.status.success(),
        "qr-read command failed: {}",
        String::from_utf8_lossy(&read_output.stderr)
    );
    let read_payload = String::from_utf8_lossy(&read_output.stdout);
    assert_eq!(payload.trim(), read_payload.trim());
}

#[test]
fn qr_command_generates_payload_for_finalized_invoice() {
    let fixture = finalized_invoice_without_qr_fixture();
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
    assert!(!payload.trim().is_empty(), "expected non-empty QR payload");
    let tlv = decode_tlv(&payload);
    let tags: Vec<u8> = tlv.iter().map(|(tag, _)| *tag).collect();
    assert_eq!(tags, vec![1, 2, 3, 4, 5], "finalized QR should include tags 1..5 only");

    let _ = std::fs::remove_file(fixture);
}

#[test]
fn qr_command_can_fail_on_signed_invoice() {
    let fixture = signed_invoice_fixture();
    let output = Command::new(cli_exe())
        .args(["qr", "--invoice"])
        .arg(&fixture)
        .arg("--fail-on-signed")
        .output()
        .expect("run qr command");

    assert!(!output.status.success(), "expected command to fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("is signed"),
        "expected signed-invoice failure message, got: {stderr}"
    );
}

#[test]
fn qr_read_command_outputs_existing_payload() {
    let fixture = signed_invoice_fixture();
    let output = Command::new(cli_exe())
        .args(["qr-read", "--invoice"])
        .arg(&fixture)
        .output()
        .expect("run qr-read command");

    assert!(
        output.status.success(),
        "qr-read command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = String::from_utf8_lossy(&output.stdout);
    assert!(!payload.trim().is_empty(), "expected non-empty QR payload");
}

#[test]
fn qr_read_command_fails_for_finalized_invoice() {
    let fixture = finalized_invoice_without_qr_fixture();
    let output = Command::new(cli_exe())
        .args(["qr-read", "--invoice"])
        .arg(&fixture)
        .output()
        .expect("run qr-read command");

    assert!(!output.status.success(), "expected qr-read to fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to parse signed invoice"),
        "expected signed-parse error, got: {stderr}"
    );

    let _ = std::fs::remove_file(fixture);
}

#[test]
fn qr_command_fail_on_signed_does_not_block_finalized_invoice() {
    let fixture = finalized_invoice_without_qr_fixture();
    let output = Command::new(cli_exe())
        .args(["qr", "--invoice"])
        .arg(&fixture)
        .arg("--fail-on-signed")
        .output()
        .expect("run qr command");

    assert!(
        output.status.success(),
        "expected finalized invoice to pass with --fail-on-signed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = String::from_utf8_lossy(&output.stdout);
    assert!(!payload.trim().is_empty(), "expected non-empty QR payload");

    let _ = std::fs::remove_file(fixture);
}

#[test]
fn generate_hash_outputs_expected() {
    let fixture = signed_invoice_fixture();
    let xml = std::fs::read_to_string(&fixture).expect("read fixture");
    let signed = parse_signed_invoice_xml(&xml).expect("parse signed invoice");
    let expected = signed.hash_base64().expect("compute hash");

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
    let xml = std::fs::read_to_string(&fixture).expect("read xml");
    let signed = parse_signed_invoice_xml(&xml).expect("parse signed invoice");

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
    let payload =
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("parse json output");
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
