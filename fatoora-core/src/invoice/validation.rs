use std::path::Path;

use crate::config::Config;
use libxml::{
    error::StructuredError,
    parser::Parser,
    schemas::{SchemaParserContext, SchemaValidationContext},
};

pub type ValidationResult = Result<(), Vec<String>>; // TODO: Define a proper ValidationResult struct later

fn format_validation_errors(errors: Vec<StructuredError>) -> Vec<String> {
    errors
        .into_iter()
        .map(|se| format!("{:#?}", se))
        .collect::<Vec<String>>()
}

fn build_validation_context(config: &Config) -> Result<SchemaValidationContext, Vec<String>> {
    let xsd_path = config
        .xsd_ubl_path
        .to_str()
        .ok_or_else(|| vec!["Invalid XSD path".to_string()])?;

    let mut parser_ctx = SchemaParserContext::from_file(xsd_path);
    SchemaValidationContext::from_parser(&mut parser_ctx).map_err(format_validation_errors)
}

pub fn validate_xml_invoice_from_file(path: &Path, config: &Config) -> ValidationResult {
    // check if file exists because libxml will just unhelpfully error out otherwise
    if !path.exists() {
        return Err(vec![format!("File not found: {}", path.display())]);
    }

    let xml_path = path
        .to_str()
        .ok_or_else(|| vec!["Invalid XML path".to_string()])?;

    let mut validation_ctx = build_validation_context(config)?;
    validation_ctx
        .validate_file(xml_path)
        .map_err(format_validation_errors)
}

pub fn validate_xml_invoice_from_str(xml: &str, config: &Config) -> ValidationResult {
    let mut validation_ctx = build_validation_context(config)?;
    let document = Parser::default()
        .parse_string(xml)
        .map_err(|e| vec![format!("Failed to parse XML: {:#?}", e)])?;

    validation_ctx
        .validate_document(&document)
        .map_err(format_validation_errors)
}
