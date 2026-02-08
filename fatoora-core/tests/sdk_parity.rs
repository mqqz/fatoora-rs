mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fatoora_core::config::Config;
use fatoora_core::invoice::validation::validate_xml_invoice_from_str;
use fatoora_core::invoice::xml::ToXml;

fn official_cli() -> Option<PathBuf> {
    std::env::var("FATOORA_CLI")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
}

fn should_skip() -> bool {
    official_cli().is_none()
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

fn run_official_stdout(args: &[&str]) -> Option<String> {
    let cli = official_cli()?;
    let output = Command::new(cli).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[test]
fn sdk_parity_hash_matches_official_cli() {
    if should_skip() {
        return;
    }

    let invoice = common::dummy_finalized_invoice();
    let xml = invoice.to_xml().expect("serialize invoice");
    let path = temp_xml_path("hash");
    std::fs::write(&path, xml).expect("write temp xml");

    // TODO: confirm official SDK args. Defaults assume ZATCA SDK CLI flags.
    let sdk_hash = run_official_stdout(&["-generateHash", "-invoice", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);

    let sdk_hash = match sdk_hash {
        Some(value) => value,
        None => return,
    };
    let our_hash = invoice.hash_base64().expect("hash");
    assert_eq!(our_hash.trim(), sdk_hash.trim(), "hash mismatch");
}

#[test]
fn sdk_parity_validation_matches_official_cli() {
    if should_skip() {
        return;
    }

    let invoice = common::dummy_finalized_invoice();
    let xml = invoice.to_xml().expect("serialize invoice");
    let path = temp_xml_path("validate");
    std::fs::write(&path, &xml).expect("write temp xml");

    // TODO: confirm official SDK args. Defaults assume ZATCA SDK CLI flags.
    let sdk_ok = match official_cli() {
        Some(cli) => Command::new(cli)
            .args(["-validate", "-invoice", path.to_str().unwrap()])
            .status()
            .ok()
            .map(|s| s.success())
            .unwrap_or(false),
        None => {
            let _ = std::fs::remove_file(&path);
            return;
        }
    };

    let _ = std::fs::remove_file(&path);

    let cfg = Config::default();
    let our_ok = validate_xml_invoice_from_str(&xml, &cfg).is_ok();
    assert_eq!(our_ok, sdk_ok, "validation result mismatch");
}
