//! XML schema validation helpers.
use crate::config::Config;
use crate::invoice::xml::dom;
use libxml::{
    parser::{Parser, ParserOptions},
    schemas::{SchemaParserContext, SchemaValidationContext},
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Re-exported so callers can name the errors [`XmlValidationError`] carries.
pub use libxml::error::StructuredError as ValidationError;

pub type ValidationResult = Result<(), XmlValidationError>;

/// Errors emitted during XML schema validation.
#[derive(Debug, Error)]
pub enum XmlValidationError {
    #[error("schema parser error: {message}")]
    SchemaParse { message: String },
    #[error("XML parse error: {message}")]
    XmlParse { message: String },
    #[error("schema validation error")]
    SchemaValidation { errors: Vec<ValidationError> },
}

fn bundled_xsd_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/schemas/UBL2.1/xsd/UBL-Invoice-2.1.xsd")
}

/// Keep libxml2 validation until a published uppsala release rejects invalid
/// inherited simple content and child elements in simple content. The public
/// API regression tests in tests/validation.rs cover both upstream defects.
/// A fresh context is needed per call: libxml2 validation contexts are mutable
/// and cannot be shared between threads.
fn build_validator() -> Result<SchemaValidationContext, String> {
    let path = bundled_xsd_path();
    check_imports_present(&path)?;
    let path = path
        .to_str()
        .ok_or_else(|| format!("invalid XSD path: {}", path.display()))?;
    let mut parser = SchemaParserContext::from_file(path);
    SchemaValidationContext::from_parser(&mut parser).map_err(|errors| format!("{errors:?}"))
}

/// Fail if any schema in the import closure of `root` is missing from disk.
///
/// Check the entire local import closure before compiling it so an incomplete
/// asset directory is always a schema-loading error, regardless of how the
/// validation engine handles unresolved imports.
fn check_imports_present(root: &Path) -> Result<(), String> {
    let mut visited = HashSet::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(path) = pending.pop() {
        let canonical = path
            .canonicalize()
            .map_err(|e| format!("missing schema {}: {e}", path.display()))?;
        if !visited.insert(canonical) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read schema {}: {e}", path.display()))?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        for location in schema_locations(&text)? {
            pending.push(dir.join(location));
        }
    }
    Ok(())
}

/// The `schemaLocation` values of an XSD's `xs:import` / `xs:include` elements.
fn schema_locations(xsd: &str) -> Result<Vec<String>, String> {
    let mut doc = uppsala::parse(xsd).map_err(|e| e.to_string())?;
    doc.prepare_xpath();
    let eval = dom::evaluator();
    let nodes = dom::nodes(
        eval,
        &doc,
        "//*[local-name()='import' or local-name()='include' or local-name()='redefine']/@schemaLocation",
    )
    .map_err(|e| e.to_string())?;

    Ok(nodes
        .into_iter()
        .map(|id| dom::string_value(&doc, id))
        .filter(|location| !location.is_empty() && !location.contains("://"))
        .collect())
}

/// Validate an XML invoice string against the UBL schema.
///
/// # Errors
/// Returns [`XmlValidationError`] if the XML is invalid or validation fails.
pub fn validate_xml_invoice_from_str(xml: &str, _config: &Config) -> ValidationResult {
    let mut validator =
        build_validator().map_err(|message| XmlValidationError::SchemaParse { message })?;
    // libxml defaults to recovering malformed XML. Validation must reject the
    // supplied document rather than validate a repaired tree.
    let document = Parser::default()
        .parse_string_with_options(
            xml,
            ParserOptions {
                recover: false,
                ..ParserOptions::default()
            },
        )
        .map_err(|e| XmlValidationError::XmlParse {
            message: format!("{e}"),
        })?;

    validator
        .validate_document(&document)
        .map_err(|errors| XmlValidationError::SchemaValidation { errors })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A schema directory that is missing one of its imports must be an error,
    /// not a validator that quietly accepts everything.
    #[test]
    fn import_closure_check_rejects_a_missing_schema() {
        let dir = std::env::temp_dir().join(format!(
            "fatoora-schema-closure-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp schema dir");
        let root = dir.join("root.xsd");
        std::fs::write(
            &root,
            r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
                 <xs:include schemaLocation="present.xsd"/>
                 <xs:include schemaLocation="absent.xsd"/>
               </xs:schema>"#,
        )
        .expect("write root schema");
        std::fs::write(
            dir.join("present.xsd"),
            r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>"#,
        )
        .expect("write imported schema");

        let missing = check_imports_present(&root).expect_err("absent.xsd is not there");
        assert!(missing.contains("absent.xsd"), "unexpected: {missing}");

        std::fs::write(
            dir.join("absent.xsd"),
            r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>"#,
        )
        .expect("write remaining schema");
        check_imports_present(&root).expect("closure is complete");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The bundled UBL schema must compile, and its import closure must be
    /// whole — the test suite is the only place that notices if the assets
    /// directory loses a file.
    #[test]
    fn bundled_schema_closure_is_complete() {
        check_imports_present(&bundled_xsd_path()).expect("bundled schema closure");
    }
}
