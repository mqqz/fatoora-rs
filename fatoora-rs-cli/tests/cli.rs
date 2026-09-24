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
    assert_eq!(
        tags,
        vec![1, 2, 3, 4, 5],
        "finalized QR should include tags 1..5 only"
    );

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

const PREVIOUS_HASH: &str =
    "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==";
const EVALUATED_AT: &str = "2026-09-23T12:00:00+03:00";

fn standard_invoice_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fatoora-core/tests/fixtures/sdk-parity/cases/standard-invoice/input.xml")
}

fn validate_zatca(path: &std::path::Path, extra: &[&str]) -> std::process::Output {
    Command::new(cli_exe())
        .args([
            "validate",
            "--profile",
            "zatca",
            "--format",
            "json",
            "--invoice",
        ])
        .arg(path)
        .args(["--evaluated-at", EVALUATED_AT])
        .args(extra)
        .output()
        .expect("run ZATCA validation command")
}

fn validation_json(output: &std::process::Output, expected_exit: i32) -> serde_json::Value {
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout must contain exactly one JSON value")
}

#[test]
fn zatca_cli_distinguishes_valid_incomplete_and_rejected_results() {
    let fixture = standard_invoice_fixture();
    let valid = validation_json(
        &validate_zatca(&fixture, &["--previous-invoice-hash", PREVIOUS_HASH]),
        0,
    );
    assert_eq!(valid["profile"], "zatca-sdk-238-R3.4.8");
    assert_eq!(valid["evaluated_at"], EVALUATED_AT);
    assert_eq!(valid["is_valid"], true);
    assert_eq!(
        valid["stages"][1]["evaluated_assertions"]
            .as_array()
            .unwrap()
            .len(),
        105
    );
    assert_eq!(
        valid["stages"][2]["evaluated_assertions"]
            .as_array()
            .unwrap()
            .len(),
        152
    );
    assert_eq!(valid["stages"][3]["status"], "not_applicable");
    assert_eq!(valid["stages"][5]["status"], "completed");

    let incomplete = validation_json(&validate_zatca(&fixture, &[]), 4);
    assert_eq!(incomplete["stages"][5]["status"], "context_required");
    assert_eq!(incomplete["is_complete"], false);
    assert_eq!(incomplete["has_errors"], false);

    let rejected = validation_json(
        &validate_zatca(
            &fixture,
            &[
                "--previous-invoice-hash",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ],
        ),
        2,
    );
    assert_eq!(rejected["stages"][5]["status"], "completed");
    assert_eq!(rejected["is_valid"], false);
    assert_eq!(rejected["has_errors"], true);
    assert!(
        rejected["stages"][5]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["severity"] == "error")
    );
}

#[test]
fn zatca_cli_schema_rejection_precedes_incomplete_status_and_retains_findings() {
    let path = unique_temp_path("schema-rejected");
    std::fs::write(&path, "<not-an-invoice/>").unwrap();
    let output = validate_zatca(&path, &[]);
    std::fs::remove_file(&path).unwrap();
    let report = validation_json(&output, 2);
    assert_eq!(report["stages"][0]["status"], "completed");
    assert_eq!(report["stages"][0]["findings"][0]["code"], "XSD_INVALID");
    assert_eq!(report["stages"][1]["status"], "not_run");
}

#[test]
fn zatca_cli_execution_failures_serialize_the_partial_report() {
    let path = unique_temp_path("malformed-validation");
    std::fs::write(&path, "<Invoice").unwrap();
    let output = validate_zatca(&path, &[]);
    std::fs::remove_file(&path).unwrap();
    let error = validation_json(&output, 3);
    assert_eq!(error["kind"], "invalid_xml");
    assert_eq!(error["report"]["stages"][0]["status"], "not_run");

    let xml = std::fs::read_to_string(standard_invoice_fixture()).unwrap();
    let changed = xml.replacen(
        "<cbc:LineExtensionAmount currencyID=\"SAR\">300.00",
        "<cbc:LineExtensionAmount currencyID=\"[\">300.00",
        1,
    );
    assert_ne!(changed, xml);
    let path = unique_temp_path("rule-execution-validation");
    std::fs::write(&path, changed).unwrap();
    let output = validate_zatca(&path, &[]);
    std::fs::remove_file(&path).unwrap();
    let error = validation_json(&output, 3);
    assert_eq!(error["kind"], "rule_evaluation");
    assert_eq!(error["stage"], "ksa");
    assert_eq!(error["assertion_site"], "ksa:112:BR-KSA-CL-02");
    assert_eq!(error["report"]["stages"][1]["status"], "completed");
    assert_eq!(error["report"]["stages"][2]["status"], "evaluation_failed");
}

#[test]
fn zatca_cli_reports_file_and_option_errors_without_inventing_a_report() {
    let missing = unique_temp_path("absent-validation-file");
    let error = validation_json(&validate_zatca(&missing, &[]), 3);
    assert_eq!(error["kind"], "io");
    assert!(error.get("report").is_none());
    let output = Command::new(cli_exe())
        .args(["validate", "--profile=zatca", "--format=json", "--invoice"])
        .arg(&missing)
        .args(["--evaluated-at", "invalid-time"])
        .output()
        .unwrap();
    let error = validation_json(&output, 3);
    assert_eq!(error["kind"], "invalid_options");
    assert!(error.get("report").is_none());
    let invalid_hash = validation_json(
        &validate_zatca(
            &standard_invoice_fixture(),
            &["--previous-invoice-hash", "bad"],
        ),
        3,
    );
    assert_eq!(invalid_hash["kind"], "invalid_context");
    assert!(invalid_hash.get("report").is_some());
}

#[test]
fn validation_usage_errors_keep_clap_diagnostics_and_exit_code() {
    for arguments in [
        vec!["--unrecognized-option"],
        vec!["--previous-invoice-hash"],
    ] {
        let output = Command::new(cli_exe())
            .args(["validate", "--profile=zatca", "--format=json", "--invoice"])
            .arg(standard_invoice_fixture())
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn xsd_cli_json_is_schema_only_and_rejects_zatca_context_flags() {
    let output = Command::new(cli_exe())
        .args(["validate", "--format", "json", "--invoice"])
        .arg(standard_invoice_fixture())
        .output()
        .unwrap();
    let report = validation_json(&output, 0);
    assert_eq!(report["layers_checked"], serde_json::json!(["xsd"]));
    assert_eq!(report["issues"], serde_json::json!([]));
    for (flag, value) in [
        ("--evaluated-at", EVALUATED_AT),
        ("--previous-invoice-hash", PREVIOUS_HASH),
    ] {
        let output = Command::new(cli_exe())
            .args(["validate", "--format", "json", "--invoice"])
            .arg(standard_invoice_fixture())
            .args([flag, value])
            .output()
            .unwrap();
        let error = validation_json(&output, 3);
        assert_eq!(error["kind"], "invalid_options");
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("--profile zatca")
        );
    }
}

#[test]
fn xsd_cli_preserves_default_text_failure_and_returns_json_findings_on_request() {
    let path = unique_temp_path("xsd-cli-invalid");
    std::fs::write(&path, "<not-an-invoice/>").unwrap();
    let legacy = Command::new(cli_exe())
        .args(["validate", "--invoice"])
        .arg(&path)
        .output()
        .unwrap();
    let structured = Command::new(cli_exe())
        .args(["validate", "--format", "json", "--invoice"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(legacy.status.code(), Some(1));
    assert!(legacy.stdout.is_empty());
    assert!(String::from_utf8_lossy(&legacy.stderr).contains("XML validation failed"));
    let report = validation_json(&structured, 2);
    assert_eq!(report["layers_checked"], serde_json::json!(["xsd"]));
    assert_eq!(report["issues"][0]["code"], "XSD_INVALID");
}

#[test]
fn zatca_cli_text_names_profile_stages_and_finding_locations() {
    let output = Command::new(cli_exe())
        .args(["validate", "--profile", "zatca", "--invoice"])
        .arg(standard_invoice_fixture())
        .args([
            "--evaluated-at",
            EVALUATED_AT,
            "--previous-invoice-hash",
            PREVIOUS_HASH,
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("zatca-sdk-238-R3.4.8"));
    assert!(text.contains("ksa: completed"));
    assert!(text.contains("signature: not_applicable"));
    assert!(text.contains("warning BR-"));
    assert!(text.contains("local-name()"));
}

#[test]
fn zatca_cli_bounds_file_reads_and_preserves_capacity_reports() {
    use std::io::{Seek, SeekFrom, Write};
    for multibyte in [false, true] {
        let path = unique_temp_path("zatca-capacity");
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(256 * 1024 * 1024).unwrap();
        if multibyte {
            file.seek(SeekFrom::Start(8 * 1024 * 1024)).unwrap();
            file.write_all("€".as_bytes()).unwrap();
        }
        drop(file);
        let result = validation_json(&validate_zatca(&path, &[]), 3);
        assert_eq!(result["kind"], "capacity_exceeded");
        assert_eq!(result["report"]["is_valid"], false);
        assert!(
            result["report"]["stages"]
                .as_array()
                .unwrap()
                .iter()
                .all(|stage| stage["status"] == "not_run")
        );
        std::fs::remove_file(path).unwrap();
    }
}
