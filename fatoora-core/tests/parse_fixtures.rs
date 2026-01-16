use fatoora_core::invoice::xml::parse::{
    parse_finalized_invoice_xml_file, parse_signed_invoice_xml_file,
};
use std::path::{Path, PathBuf};

fn collect_xml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(read_dir) = std::fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "xml") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn parse_standard_and_simplified_invoices() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/invoices");
    let standard = root.join("Standard/Invoice");
    let simplified = root.join("Simplified/Invoice");

    let files = collect_xml_files(&standard)
        .into_iter()
        .chain(collect_xml_files(&simplified))
        .collect::<Vec<_>>();

    assert!(!files.is_empty(), "no invoice fixtures found");

    for file in files {
        parse_finalized_invoice_xml_file(&file)
            .unwrap_or_else(|e| panic!("failed to parse {:?}: {e:?}", file));
        parse_signed_invoice_xml_file(&file)
            .unwrap_or_else(|e| panic!("failed to parse signed {:?}: {e:?}", file));
    }
}

#[test]
fn parse_credit_debit_invoices() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/invoices");
    let standard_credit = root.join("Standard/Credit");
    let standard_debit = root.join("Standard/Debit");
    let simplified_credit = root.join("Simplified/Credit");
    let simplified_debit = root.join("Simplified/Debit");

    let files = collect_xml_files(&standard_credit)
        .into_iter()
        .chain(collect_xml_files(&standard_debit))
        .chain(collect_xml_files(&simplified_credit))
        .chain(collect_xml_files(&simplified_debit))
        .collect::<Vec<_>>();

    assert!(!files.is_empty(), "no credit/debit fixtures found");

    for file in files {
        let invoice = parse_finalized_invoice_xml_file(&file)
            .unwrap_or_else(|e| panic!("failed to parse {:?}: {e:?}", file));
        match invoice.data().invoice_type() {
            fatoora_core::invoice::InvoiceType::CreditNote(_, original, _)
            | fatoora_core::invoice::InvoiceType::DebitNote(_, original, _) => {
                assert_eq!(original.id(), "SME00002");
            }
            _ => panic!("expected credit/debit invoice type for {:?}", file),
        }
        parse_signed_invoice_xml_file(&file)
            .unwrap_or_else(|e| panic!("failed to parse signed {:?}: {e:?}", file));
    }
}
