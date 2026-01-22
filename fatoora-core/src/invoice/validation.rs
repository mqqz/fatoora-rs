//! XML schema validation helpers.
use crate::config::Config;
use libxml::{
    error::StructuredError,
    parser::Parser,
    schemas::{SchemaParserContext, SchemaValidationContext},
};
use std::path::PathBuf;
use thiserror::Error;

pub type ValidationResult = Result<(), XmlValidationError>;

/// Errors emitted during XML schema validation.
#[derive(Debug, Error)]
pub enum XmlValidationError {
    #[error("invalid XSD path: {path}")]
    InvalidXsdPath { path: String },
    #[error("schema parser error")]
    SchemaParse { errors: Vec<StructuredError> },
    #[error("XML parse error: {message}")]
    XmlParse { message: String },
    #[error("schema validation error")]
    SchemaValidation { errors: Vec<StructuredError> },
}

fn bundled_xsd_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd")
}

fn build_validation_context(_config: &Config) -> Result<SchemaValidationContext, XmlValidationError> {
    let xsd_path_buf = bundled_xsd_path();
    let xsd_path = xsd_path_buf.to_str().ok_or_else(|| {
        XmlValidationError::InvalidXsdPath {
            path: xsd_path_buf.display().to_string(),
        }
    })?;

    let mut parser_ctx = SchemaParserContext::from_file(xsd_path);
    SchemaValidationContext::from_parser(&mut parser_ctx)
        .map_err(|errors| XmlValidationError::SchemaParse { errors })
}

/// Validate an XML invoice string against the UBL schema.
///
/// # Errors
/// Returns [`XmlValidationError`] if the XML is invalid or validation fails.
pub fn validate_xml_invoice_from_str(xml: &str, config: &Config) -> ValidationResult {
    let mut validation_ctx = build_validation_context(config)?;
    let document = Parser::default()
        .parse_string(xml)
        .map_err(|e| XmlValidationError::XmlParse {
            message: format!("{e:?}"),
        })?;

    validation_ctx
        .validate_document(&document)
        .map_err(|errors| XmlValidationError::SchemaValidation { errors })
}
