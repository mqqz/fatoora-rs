//! XML schema validation and shared validation reports.
//!
//! XSD checks do not run builder field checks, business rules, or signature
//! verification. Parsing a signed invoice does not verify its signature.
mod report;
use crate::config::Config;
use libxml::{
    parser::{Parser, ParserOptions},
    schemas::{SchemaParserContext, SchemaValidationContext},
};
pub use report::{
    Severity, ValidationFinding, ValidationLayer, ValidationLocation, ValidationReport,
};
use std::path::PathBuf;
use thiserror::Error;

pub type ValidationResult = Result<(), XmlValidationError>;

/// Errors emitted during XML schema validation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum XmlValidationError {
    #[error("invalid XSD path: {path}")]
    InvalidXsdPath { path: String },
    #[error("schema parser error")]
    SchemaParse { errors: Vec<crate::Diagnostic> },
    #[error("XML parse error: {message}")]
    XmlParse { message: String },
    #[error("schema validation error")]
    SchemaValidation { errors: Vec<crate::Diagnostic> },
}

impl XmlValidationError {
    /// Shared classification used by bindings.
    pub fn kind(&self) -> crate::ErrorKind {
        match self {
            Self::InvalidXsdPath { .. } => crate::ErrorKind::InvalidInput,
            Self::SchemaParse { .. } => crate::ErrorKind::Parse,
            Self::XmlParse { .. } => crate::ErrorKind::Xml,
            Self::SchemaValidation { .. } => crate::ErrorKind::Validation,
        }
    }
}

fn bundled_xsd_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd")
}

fn build_validation_context(
    _config: &Config,
) -> Result<SchemaValidationContext, XmlValidationError> {
    let xsd_path_buf = bundled_xsd_path();
    let xsd_path = xsd_path_buf
        .to_str()
        .ok_or_else(|| XmlValidationError::InvalidXsdPath {
            path: xsd_path_buf.display().to_string(),
        })?;

    let mut parser_ctx = SchemaParserContext::from_file(xsd_path);
    SchemaValidationContext::from_parser(&mut parser_ctx).map_err(|errors| {
        XmlValidationError::SchemaParse {
            errors: errors
                .into_iter()
                .map(crate::Diagnostic::from_xml)
                .collect(),
        }
    })
}

/// Validate an XML invoice string against the UBL schema only.
///
/// Success establishes XSD conformance, not business-rule compliance or signature
/// authenticity. See [`validate_xml_invoice_report_from_str`] for explicit coverage.
///
/// # Errors
/// Returns [`XmlValidationError`] if the XML is invalid or validation fails.
pub fn validate_xml_invoice_from_str(xml: &str, config: &Config) -> ValidationResult {
    let mut validation_ctx = build_validation_context(config)?;
    let document = Parser::default()
        .parse_string_with_options(
            xml,
            ParserOptions {
                recover: false,
                ..ParserOptions::default()
            },
        )
        .map_err(|e| XmlValidationError::XmlParse {
            message: format!("{e:?}"),
        })?;

    validation_ctx
        .validate_document(&document)
        .map_err(|errors| XmlValidationError::SchemaValidation {
            errors: errors
                .into_iter()
                .map(crate::Diagnostic::from_xml)
                .collect(),
        })
}

/// Check the bundled UBL XSD and return findings with explicit layer coverage.
///
/// Schema violations return `Ok(report)` with error findings. Only the XSD layer
/// is marked checked, even when the input contains a signature. Source locations
/// are included only when supplied by the backend. Fatal diagnostics are errors.
///
/// # Errors
/// Returns [`XmlValidationError`] when the schema cannot be loaded or parsed, or
/// the input is not parseable XML. In those cases XSD validation did not complete.
pub fn validate_xml_invoice_report_from_str(
    xml: &str,
    config: &Config,
) -> Result<ValidationReport, XmlValidationError> {
    let issues = match validate_xml_invoice_from_str(xml, config) {
        Ok(()) => Vec::new(),
        Err(XmlValidationError::SchemaValidation { errors }) => {
            let mut findings: Vec<_> = errors
                .into_iter()
                .map(|diagnostic| ValidationFinding {
                    layer: ValidationLayer::Xsd,
                    code: "XSD_INVALID".to_owned(),
                    severity: match diagnostic.severity() {
                        Some(crate::DiagnosticSeverity::Warning) => Severity::Warning,
                        _ => Severity::Error,
                    },
                    message: diagnostic.message().to_owned(),
                    location: diagnostic.line().map(|line| ValidationLocation::Xml {
                        line,
                        column: diagnostic.column(),
                    }),
                })
                .collect();
            // A backend failure must remain a failure even if it supplies no
            // diagnostics, or only warning diagnostics.
            if !findings
                .iter()
                .any(|finding| finding.severity == Severity::Error)
            {
                findings.push(ValidationFinding {
                    layer: ValidationLayer::Xsd,
                    code: "XSD_INVALID".to_owned(),
                    severity: Severity::Error,
                    message: "XML failed schema validation".to_owned(),
                    location: None,
                });
            }
            findings
        }
        Err(error) => return Err(error),
    };
    Ok(ValidationReport {
        layers_checked: vec![ValidationLayer::Xsd],
        issues,
    })
}
