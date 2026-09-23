use super::{build_validation_context, compile, materialize};
use crate::{
    config::Config,
    invoice::validation::{
        XmlValidationError, validate_xml_invoice_from_str, validate_xml_invoice_report_from_str,
    },
};
use libxml::parser::{Parser, ParserOptions};

const INVOICE: &str =
    include_str!("../../../tests/fixtures/invoices/sample-simplified-invoice.xml");

#[test]
fn compiled_schema_validates_after_extracted_resources_are_removed() {
    let resources = materialize().unwrap();
    let directory = resources.path().to_path_buf();
    let mut context = compile(resources.path()).unwrap();
    drop(resources);
    assert!(
        !directory.exists(),
        "schema extraction must clean up its files"
    );
    let document = Parser::default().parse_string(INVOICE).unwrap();
    context.validate_document(&document).unwrap();
    let invalid = Parser::default().parse_string("<not-an-invoice/>").unwrap();
    assert!(context.validate_document(&invalid).is_err());
}

#[test]
fn extraction_preserves_bundled_bytes_and_uses_private_unique_directories() {
    let first = materialize().unwrap();
    let second = materialize().unwrap();
    assert_ne!(first.path(), second.path());
    for (relative, bytes) in super::RESOURCES {
        assert_eq!(std::fs::read(first.path().join(relative)).unwrap(), *bytes);
        assert_eq!(std::fs::read(second.path().join(relative)).unwrap(), *bytes);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(first.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(second.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[test]
fn schema_resources_preserve_public_success_and_failure_contracts() {
    validate_xml_invoice_from_str(INVOICE, &Config::default()).unwrap();
    let report =
        validate_xml_invoice_report_from_str("<not-an-invoice/>", &Config::default()).unwrap();
    assert!(report.has_errors());
    assert!(matches!(
        validate_xml_invoice_from_str("<not-an-invoice/>", &Config::default()),
        Err(XmlValidationError::SchemaValidation { .. })
    ));
    assert!(matches!(
        validate_xml_invoice_from_str("<Invoice", &Config::default()),
        Err(XmlValidationError::XmlParse { .. })
    ));
}

#[test]
fn independent_schema_contexts_compile_and_validate_in_parallel() {
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let mut context = build_validation_context().unwrap();
                    let document = Parser::default()
                        .parse_string_with_options(
                            INVOICE,
                            ParserOptions {
                                recover: false,
                                no_net: true,
                                ..ParserOptions::default()
                            },
                        )
                        .unwrap();
                    context.validate_document(&document).unwrap();
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    });
}
