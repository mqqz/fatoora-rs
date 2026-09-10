use std::path::{Path, PathBuf};

use crate::invoice::sign::invoice_hash_base64;
use crate::invoice::xml::dom;
use uppsala::{Document, XPathEvaluator};

#[test]
fn fixture_invoices_match_hash_digest() {
    let fixtures_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/invoices");
    let files = collect_xml_files(&fixtures_root);
    assert!(!files.is_empty(), "no fixture invoices found");

    for file in files {
        let xml = std::fs::read_to_string(&file).expect("read fixture");
        let doc = dom::parse(&xml).expect("parse fixture");
        let eval = dom::evaluator();

        let expected_invoice_digest = xpath_text(
            eval,
            &doc,
            "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@Id='invoiceSignedData']/ds:DigestValue",
            "invoiceSignedData DigestValue",
        );
        let actual_invoice_digest = invoice_hash_base64(&doc).expect("invoice hash");
        assert_eq!(
            expected_invoice_digest,
            actual_invoice_digest,
            "invoice hash mismatch for {}",
            file.display()
        );
    }
}

fn xpath_text(eval: &XPathEvaluator, doc: &Document<'_>, expr: &str, label: &str) -> String {
    let value = dom::text(eval, doc, expr)
        .unwrap_or_else(|_| panic!("XPath error for {label}"))
        .unwrap_or_else(|| panic!("Missing {label} in invoice XML"));
    assert!(!value.is_empty(), "Empty {label} in invoice XML");
    value
}

fn collect_xml_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).expect("read dir");
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("xml") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}
