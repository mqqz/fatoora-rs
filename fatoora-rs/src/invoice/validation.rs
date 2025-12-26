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

// Backwards compatibility with the previous API
pub fn validate_xml_invoice(path: &Path, config: &Config) -> ValidationResult {
    validate_xml_invoice_from_file(path, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invoice::{dummy_invoice, xml::ToXml};

    #[test]
    fn test_validate_xml_invoice() {
        let config = Default::default();
        let result = validate_xml_invoice_from_file(
            Path::new("./assets/test/invoices/sample-simplified-invoice.xml"),
            &config,
        );
        match result {
            Ok(_) => (),
            Err(errors) => {
                for error in errors {
                    println!("Validation error: {}", error);
                }
                panic!("XML validation failed");
            }
        }
    }

    #[test]
    fn test_our_invoices_can_be_validated() {
        let config: Config = Default::default();
        let xml_invoice = dummy_invoice()
            .to_xml()
            .expect("failed to serialize dummy invoice");

        let result = validate_xml_invoice_from_str(&xml_invoice, &config);
        match result {
            Ok(_) => (),
            Err(errors) => {
                for error in errors {
                    println!("Validation error: {}", error);
                }
                panic!("XML validation failed");
            }
        }
    }
}
