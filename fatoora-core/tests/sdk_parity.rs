mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{Mutex, OnceLock};

use base64ct::{Base64, Encoding};
use fatoora_core::config::Config;
use fatoora_core::invoice::validation::validate_xml_invoice_from_str;
use fatoora_core::invoice::xml::ToXml;
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

const SDK_CLI: &str = "fatoora";
const SDK_CERT_DIR_REL: &str = "Data/Certificates";

static SDK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_sdk_lock<T>(f: impl FnOnce() -> T) -> T {
    let lock = SDK_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().expect("sdk lock");
    f()
}

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

    let cert_b64_wrapped = std::fs::read_to_string(cert_b64_path).ok()?;
    // The fixture is base64-of-base64; decode once to get the PEM body.
    let cert_b64_bytes = Base64::decode_vec(cert_b64_wrapped.trim()).ok()?;
    let cert_b64 = String::from_utf8(cert_b64_bytes).ok()?;

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
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Some(combined);
    }
    Some(combined)
}

fn sign_with_sdk(xml: &str, label: &str) -> Option<String> {
    let in_tag = format!("sign-in-{label}");
    let out_tag = format!("sign-out-{label}");
    let in_path = temp_xml_path(&in_tag);
    let out_path = temp_xml_path(&out_tag);
    std::fs::write(&in_path, xml).ok()?;

    let cli = find_cli()?;
    let output = Command::new(cli)
        .args([
            "-sign",
            "-invoice",
            in_path.to_str().unwrap(),
            "-signedInvoice",
            out_path.to_str().unwrap(),
        ])
        .output()
        .ok()?;

    let _ = std::fs::remove_file(&in_path);

    if !output.status.success() {
        let _ = std::fs::remove_file(&out_path);
        return None;
    }

    let signed_xml = std::fs::read_to_string(&out_path).ok()?;
    let _ = std::fs::remove_file(&out_path);
    Some(signed_xml)
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

// NOTE: Our Rust validator currently checks only UBL XSD schema validity.
// The ZATCA SDK performs *global* validation that includes KSA-specific
// business rules (e.g., timing/clearance/QR/signature rules). To keep parity
// meaningful, we compare our result to the SDK's XSD result only.
//
// When we add KSA rule validation in Rust, extend this file to also parse and
// compare the SDK's "GLOBAL VALIDATION RESULT" line in addition to (or
// instead of) the XSD result.
fn parse_sdk_xsd_validation(output: &str) -> Option<bool> {
    for line in output.lines() {
        if line.contains("[XSD] validation result") {
            let upper = line.to_ascii_uppercase();
            if upper.contains("PASSED") {
                return Some(true);
            }
            if upper.contains("FAILED") {
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

    with_sdk_lock(|| {
        if stage_sdk_credentials().is_none() {
            return;
        }

        for (label, invoice) in parity_invoices() {
            let xml = invoice.to_xml().expect("serialize invoice");
            let tag = format!("hash-{label}");
            let path = temp_xml_path(&tag);
            std::fs::write(&path, xml).expect("write temp xml");

            let sdk_output =
                run_official_output(&["-generateHash", "-invoice", path.to_str().unwrap()])
                    .expect("sdk hash output");
            let _ = std::fs::remove_file(&path);

            let sdk_hash = parse_sdk_hash(&sdk_output)
                .unwrap_or_else(|| panic!("parse sdk hash failed for {label}. output:\n{sdk_output}"));
            let our_hash = invoice.hash_base64().expect("hash");
            assert_eq!(
                our_hash.trim(),
                sdk_hash.trim(),
                "hash mismatch for {label}"
            );
        }
    });
}

#[test]
fn sdk_parity_sign_contains_same_hash() {
    if should_skip() {
        return;
    }

    with_sdk_lock(|| {
        if stage_sdk_credentials().is_none() {
            return;
        }

        for (label, invoice) in parity_invoices() {
            let xml = invoice.to_xml().expect("serialize invoice");
            let signed_xml = sign_with_sdk(&xml, label)
                .unwrap_or_else(|| panic!("sdk sign failed for {label}"));

            let signed = parse_signed_invoice_xml(&signed_xml).expect("parse signed xml");
            let our_hash = invoice.hash_base64().expect("hash");
            assert_eq!(
                signed.invoice_hash().trim(),
                our_hash.trim(),
                "hash mismatch for {label}"
            );
        }
    });
}

#[test]
fn sdk_parity_validation_matches_official_cli() {
    if should_skip() {
        return;
    }

    with_sdk_lock(|| {
        if stage_sdk_credentials().is_none() {
            return;
        }

        for (label, invoice) in parity_invoices() {
            let xml = invoice.to_xml().expect("serialize invoice");
            let signed_xml = sign_with_sdk(&xml, &format!("validate-{label}"))
                .unwrap_or_else(|| panic!("sdk sign for validation failed for {label}"));
            let tag = format!("validate-{label}");
            let path = temp_xml_path(&tag);
            std::fs::write(&path, &signed_xml).expect("write temp xml");

            let sdk_output =
                run_official_output(&["-validate", "-invoice", path.to_str().unwrap()])
                    .expect("sdk validation output");

            let _ = std::fs::remove_file(&path);

            let sdk_ok = parse_sdk_xsd_validation(&sdk_output).unwrap_or_else(|| {
                panic!("parse sdk XSD validation failed for {label}. output:\n{sdk_output}")
            });

            let cfg = Config::default();
            let our_ok = validate_xml_invoice_from_str(&signed_xml, &cfg).is_ok();
            assert_eq!(
                our_ok, sdk_ok,
                "validation result mismatch for {label}"
            );
        }
    });
}

#[test]
fn sdk_parity_rejects_invalid_invoice() {
    if should_skip() {
        return;
    }

    with_sdk_lock(|| {
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

        let sdk_ok = parse_sdk_xsd_validation(&sdk_output).unwrap_or_else(|| {
            panic!(
                "parse sdk XSD validation failed for invalid invoice. output:\n{sdk_output}"
            )
        });
        assert!(!sdk_ok, "sdk should reject invalid invoice");

        let cfg = Config::default();
        let our_ok = validate_xml_invoice_from_str(&xml, &cfg).is_ok();
        assert!(!our_ok, "our validator should reject invalid invoice");
    });
}
