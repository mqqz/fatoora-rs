mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Encoding};
use fatoora_core::config::Config;
use fatoora_core::invoice::validation::validate_xml_invoice_from_str;
use fatoora_core::invoice::xml::ToXml;
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

const SDK_CLI: &str = "fatoora";
const SDK_CERT_DIR_REL: &str = "Data/Certificates";

fn find_in_path(cmd: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn find_in_home(cmd: &str) -> Option<PathBuf> {
    let home = std::env::var_os("FATOORA_HOME")?;
    let candidate = PathBuf::from(home).join(cmd);
    if candidate.is_file() {
        return Some(candidate);
    }
    None
}

fn find_cli() -> Option<PathBuf> {
    find_in_home(SDK_CLI).or_else(|| find_in_path(SDK_CLI))
}

fn find_sdk_cert_dir(exe_path: &Path) -> Option<PathBuf> {
    let mut current = exe_path.parent();
    while let Some(dir) = current {
        let candidate = dir.join(SDK_CERT_DIR_REL);
        if candidate.is_dir() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

fn stage_sdk_credentials() -> Option<PathBuf> {
    let exe = find_cli()?;
    let cert_dir = if let Some(home) = std::env::var_os("FATOORA_HOME") {
        let candidate = PathBuf::from(home).join(SDK_CERT_DIR_REL);
        if candidate.is_dir() {
            candidate
        } else {
            find_sdk_cert_dir(&exe)?
        }
    } else {
        find_sdk_cert_dir(&exe)?
    };

    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let cert_b64_path = fixtures_dir.join("certs/zatca_cert_b64.txt");
    let key_der_path = fixtures_dir.join("pkeys/test_zatca_pkey.der");

    let cert_b64 = std::fs::read_to_string(cert_b64_path).ok()?;
    let key_der = std::fs::read(key_der_path).ok()?;
    let key_b64 = Base64::encode_string(&key_der);

    std::fs::write(cert_dir.join("cert.pem"), cert_b64.trim()).ok()?;
    std::fs::write(cert_dir.join("ec-secp256k1-priv-key.pem"), key_b64).ok()?;

    Some(cert_dir)
}

fn should_skip() -> bool {
    find_cli().is_none()
}

fn temp_xml_path(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("fatoora-sdk-parity-{label}-{pid}-{nanos}.xml"));
    path
}

fn run_official_output(args: &[&str]) -> Option<String> {
    let cli = find_cli()?;
    let output = Command::new(cli).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Some(combined)
}

fn parse_sdk_hash(output: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(idx) = line.find("INVOICE HASH =") {
            let value = line[(idx + "INVOICE HASH =".len())..].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn parse_sdk_validation(output: &str) -> Option<bool> {
    for line in output.lines() {
        if let Some(idx) = line.find("GLOBAL VALIDATION RESULT") {
            let tail = line[(idx + "GLOBAL VALIDATION RESULT".len())..].to_ascii_uppercase();
            if tail.contains("PASSED") {
                return Some(true);
            }
            if tail.contains("FAILED") {
                return Some(false);
            }
        }
    }
    None
}

fn parity_invoices() -> Vec<(&'static str, fatoora_core::invoice::FinalizedInvoice)> {
    vec![
        ("dummy-simplified", common::dummy_finalized_invoice()),
        ("complex-standard", common::complex_standard_invoice()),
        ("credit-note", common::credit_note_standard_invoice()),
        ("debit-note", common::debit_note_standard_invoice()),
        ("prepayment-standard", common::prepayment_standard_invoice()),
        ("mixed-vat-simplified", common::mixed_vat_simplified_invoice()),
        ("export-self-billed", common::export_self_billed_standard_invoice()),
        ("out-of-scope", common::out_of_scope_standard_invoice()),
        ("simplified-credit-note", common::simplified_credit_note_invoice()),
        ("simplified-debit-note", common::simplified_debit_note_invoice()),
        ("foreign-currency", common::foreign_currency_standard_invoice()),
    ]
}

#[test]
fn sdk_parity_hash_matches_official_cli() {
    if should_skip() {
        return;
    }

    if stage_sdk_credentials().is_none() {
        return;
    }

    for (label, invoice) in parity_invoices() {
        let xml = invoice.to_xml().expect("serialize invoice");
        let tag = format!("hash-{label}");
        let path = temp_xml_path(&tag);
        std::fs::write(&path, xml).expect("write temp xml");

        let sdk_output = run_official_output(&["-generateHash", "-invoice", path.to_str().unwrap()])
            .expect("sdk hash output");
        let _ = std::fs::remove_file(&path);

        let sdk_hash = parse_sdk_hash(&sdk_output).expect("parse sdk hash");
        let our_hash = invoice.hash_base64().expect("hash");
        assert_eq!(
            our_hash.trim(),
            sdk_hash.trim(),
            "hash mismatch for {label}"
        );
    }
}

#[test]
fn sdk_parity_sign_contains_same_hash() {
    if should_skip() {
        return;
    }

    if stage_sdk_credentials().is_none() {
        return;
    }

    for (label, invoice) in parity_invoices() {
        let xml = invoice.to_xml().expect("serialize invoice");
        let in_tag = format!("sign-in-{label}");
        let out_tag = format!("sign-out-{label}");
        let in_path = temp_xml_path(&in_tag);
        let out_path = temp_xml_path(&out_tag);
        std::fs::write(&in_path, &xml).expect("write temp xml");

        let cli = find_cli().expect("sdk cli");
        let status = Command::new(cli)
            .args([
                "-sign",
                "-invoice",
                in_path.to_str().unwrap(),
                "-signedInvoice",
                out_path.to_str().unwrap(),
            ])
            .status()
            .ok()
            .expect("sdk sign");

        let _ = std::fs::remove_file(&in_path);

        assert!(status.success(), "sdk sign failed for {label}");

        let signed_xml = std::fs::read_to_string(&out_path).expect("read signed xml");
        let _ = std::fs::remove_file(&out_path);

        let signed = parse_signed_invoice_xml(&signed_xml).expect("parse signed xml");
        let our_hash = invoice.hash_base64().expect("hash");
        assert_eq!(
            signed.invoice_hash().trim(),
            our_hash.trim(),
            "hash mismatch for {label}"
        );
    }
}

#[test]
fn sdk_parity_validation_matches_official_cli() {
    if should_skip() {
        return;
    }

    if stage_sdk_credentials().is_none() {
        return;
    }

    for (label, invoice) in parity_invoices() {
        let xml = invoice.to_xml().expect("serialize invoice");
        let tag = format!("validate-{label}");
        let path = temp_xml_path(&tag);
        std::fs::write(&path, &xml).expect("write temp xml");

        let sdk_output =
            run_official_output(&["-validate", "-invoice", path.to_str().unwrap()])
                .expect("sdk validation output");

        let _ = std::fs::remove_file(&path);

        let sdk_ok = parse_sdk_validation(&sdk_output).expect("parse sdk validation");

        let cfg = Config::default();
        let our_ok = validate_xml_invoice_from_str(&xml, &cfg).is_ok();
        assert_eq!(
            our_ok, sdk_ok,
            "validation result mismatch for {label}"
        );
    }
}

#[test]
fn sdk_parity_rejects_invalid_invoice() {
    if should_skip() {
        return;
    }

    if stage_sdk_credentials().is_none() {
        return;
    }

    let invoice = common::dummy_finalized_invoice();
    let mut xml = invoice.to_xml().expect("serialize invoice");
    // Make the XML invalid by removing a required element.
    xml = xml.replace("<cbc:ID>INV-1</cbc:ID>", "");

    let path = temp_xml_path("invalid-validate");
    std::fs::write(&path, &xml).expect("write temp xml");

    let sdk_output =
        run_official_output(&["-validate", "-invoice", path.to_str().unwrap()])
            .expect("sdk validation output");

    let _ = std::fs::remove_file(&path);

    let sdk_ok = parse_sdk_validation(&sdk_output).expect("parse sdk validation");
    assert!(!sdk_ok, "sdk should reject invalid invoice");

    let cfg = Config::default();
    let our_ok = validate_xml_invoice_from_str(&xml, &cfg).is_ok();
    assert!(!our_ok, "our validator should reject invalid invoice");
}
