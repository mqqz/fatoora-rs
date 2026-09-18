//! Maintenance input/output exporter for scripts/sdk_parity.py; never run by ordinary tests.
#[path = "../tests/common/mod.rs"]
mod common;
use std::{fs, path::PathBuf};

fn main() {
    let output = PathBuf::from(std::env::args().nth(1).expect("output directory"));
    fs::create_dir_all(&output).unwrap();
    let cases = common::parity_invoices();
    let signed_mode = std::env::args().any(|a| a == "--signed");
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk-parity");
    let signer = if signed_mode {
        Some(
            fatoora_core::invoice::sign::InvoiceSigner::from_der(
                &fs::read(corpus.join("credentials/certificate.der")).unwrap(),
                &fs::read(corpus.join("credentials/private-key.der")).unwrap(),
            )
            .unwrap(),
        )
    } else {
        None
    };
    for (id, invoice) in cases {
        if let Some(signer) = &signer {
            fs::write(
                output.join(format!("{id}-typed.xml")),
                invoice.sign(signer).unwrap().xml(),
            )
            .unwrap();
        } else {
            fs::write(output.join(format!("{id}.xml")), invoice.to_xml().unwrap()).unwrap();
        }
    }
    if let Some(signer) = signer {
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(corpus.join("manifest.json")).unwrap()).unwrap();
        for case in manifest["cases"].as_array().unwrap() {
            if case["kind"] != "invoice" {
                continue;
            }
            let id = case["id"].as_str().unwrap();
            let xml = fs::read_to_string(corpus.join("cases").join(id).join("input.xml")).unwrap();
            fs::write(
                output.join(format!("{id}.xml")),
                signer.sign_xml(&xml).unwrap(),
            )
            .unwrap();
        }
    }
}
