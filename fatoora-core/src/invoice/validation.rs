//! XML schema validation helpers.
use std::path::{Path, PathBuf};

use crate::config::Config;
use libxml::{
    error::StructuredError,
    parser::Parser,
    schemas::{SchemaParserContext, SchemaValidationContext},
};
use thiserror::Error;

pub type ValidationResult = Result<(), XmlValidationError>;

/// Errors emitted during XML schema validation.
#[derive(Debug, Error)]
pub enum XmlValidationError {
    #[error("file not found: {path}")]
    FileNotFound { path: PathBuf },
    #[error("invalid XSD path: {path}")]
    InvalidXsdPath { path: String },
    #[error("schema parser error")]
    SchemaParse { errors: Vec<StructuredError> },
    #[error("invalid XML path: {path}")]
    InvalidXmlPath { path: String },
    #[error("XML parse error: {message}")]
    XmlParse { message: String },
    #[error("schema validation error")]
    SchemaValidation { errors: Vec<StructuredError> },
}

fn build_validation_context(config: &Config) -> Result<SchemaValidationContext, XmlValidationError> {
    let xsd_path = config.xsd_ubl_path().to_str().ok_or_else(|| {
        XmlValidationError::InvalidXsdPath {
            path: config.xsd_ubl_path().display().to_string(),
        }
    })?;

    let mut parser_ctx = SchemaParserContext::from_file(xsd_path);
    SchemaValidationContext::from_parser(&mut parser_ctx)
        .map_err(|errors| XmlValidationError::SchemaParse { errors })
}

/// Validate an XML invoice file against the UBL schema.
///
/// # Examples
/// ```rust,no_run
/// use fatoora_core::config::{Config, EnvironmentType};
/// use fatoora_core::invoice::validation::validate_xml_invoice_from_file;
///
/// let config = Config::new(EnvironmentType::NonProduction);
/// validate_xml_invoice_from_file("invoice.xml".as_ref(), &config)?;
/// # Ok::<(), fatoora_core::invoice::validation::XmlValidationError>(())
/// ```
///
/// # Errors
/// Returns [`XmlValidationError`] if the file cannot be read or validation fails.
pub fn validate_xml_invoice_from_file(path: &Path, config: &Config) -> ValidationResult {
    // check if file exists because libxml will just unhelpfully error out otherwise
    if !path.exists() {
        return Err(XmlValidationError::FileNotFound {
            path: path.to_path_buf(),
        });
    }

    let xml_path = path
        .to_str()
        .ok_or_else(|| XmlValidationError::InvalidXmlPath {
            path: path.display().to_string(),
        })?;

    let mut validation_ctx = build_validation_context(config)?;
    validation_ctx
        .validate_file(xml_path)
        .map_err(|errors| XmlValidationError::SchemaValidation { errors })
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
