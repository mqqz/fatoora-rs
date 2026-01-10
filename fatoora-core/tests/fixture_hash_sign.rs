use libxml::{parser::Parser, xpath};
use std::path::{Path, PathBuf};

const CBC_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";
const CAC_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";
const UBL_NS: &str = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2";
const EXT_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";
const SIG_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2";
const SAC_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2";
const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";

#[test]
fn fixture_invoices_match_hash_digest() {
    let fixtures_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/invoices");
    let files = collect_xml_files(&fixtures_root);
    assert!(!files.is_empty(), "no fixture invoices found");

    for file in files {
        let xml = std::fs::read_to_string(&file).expect("read fixture");
        let doc = Parser::default().parse_string(&xml).expect("parse fixture");
        let ctx = xpath::Context::new(&doc).expect("xpath context");

        ctx.register_namespace("cbc", CBC_NS).expect("cbc ns");
        ctx.register_namespace("cac", CAC_NS).expect("cac ns");
        ctx.register_namespace("ubl", UBL_NS).expect("ubl ns");
        ctx.register_namespace("ext", EXT_NS).expect("ext ns");
        ctx.register_namespace("sig", SIG_NS).expect("sig ns");
        ctx.register_namespace("sac", SAC_NS).expect("sac ns");
        ctx.register_namespace("ds", DS_NS).expect("ds ns");
        ctx.register_namespace("xades", XADES_NS).expect("xades ns");

        let expected_invoice_digest = xpath_text(
            &ctx,
            "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@Id='invoiceSignedData']/ds:DigestValue",
            "invoiceSignedData DigestValue",
        );
        let actual_invoice_digest =
            fatoora_core::invoice::sign::invoice_hash_base64(&doc).expect("invoice hash");
        assert_eq!(
            expected_invoice_digest, actual_invoice_digest,
            "invoice hash mismatch for {}",
            file.display()
        );
        // TODO somehow make sure our serialised signed properties match the fixture
        // let expected_signed_props_digest = xpath_text(
        //     &ctx,
        //     "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue",
        //     "SignedProperties DigestValue",
        // );
        // let actual_signed_props_digest = signed_properties_hash_from_xml(&doc);
        // assert_eq!(
        //     expected_signed_props_digest, actual_signed_props_digest,
        //     "signed properties hash mismatch for {}",
        //     file.display()
        // );
    }
}

fn xpath_text(ctx: &xpath::Context, expr: &str, label: &str) -> String {
    let nodes = ctx
        .evaluate(expr)
        .unwrap_or_else(|_| panic!("XPath error for {label}"))
        .get_nodes_as_vec();
    let node = nodes
        .first()
        .unwrap_or_else(|| panic!("Missing {label} in invoice XML"));
    let value = node.get_content().trim().to_string();
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
