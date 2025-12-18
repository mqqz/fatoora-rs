use std::path::Path;

use crate::config::Config;
use libxml::schemas::{SchemaParserContext, SchemaValidationContext};

pub type ValidationResult = Result<(), Vec<String>>; // TODO: Define a proper ValidationResult struct later

pub fn validate_xml_invoice(path: &Path, config: &Config) -> ValidationResult {
    // check if file exists because libxml will just unhelpfully error out otherwise
    if !path.exists() {
        return Err(vec![format!("File not found: {}", path.display())]);
    }
    // // load as document
    // let _doc = libxml::parser::Parser::default()
    //     .parse_file(
    //         path.to_str()
    //             .ok_or_else(|| vec!["Invalid XML path".to_string()])?,
    //     )
    //     .map_err(|e| vec![format!("Failed to parse XML: {:#?}", e)])?;
    // "Element '{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber':
    // '3791127.....' is not a valid value of the atomic type 'xs:integer'
    // the schema has been manually changed to xs:string for this field
    // so we need to validate manually here due to this workaround :(

    // load the xsd schema
    let parser_ctx = &mut SchemaParserContext::from_file(
        config
            .xsd_ubl_path
            .to_str()
            .ok_or_else(|| vec!["Invalid XSD path".to_string()])?,
    );

    let validation_ctx = &mut SchemaValidationContext::from_parser(parser_ctx)
        .map_err(|e| vec![format!("{:#?}", e)])?;
    // validate the document against the schema
    validation_ctx
        .validate_file(
            path.to_str()
                .ok_or_else(|| vec!["Invalid XML path".to_string()])?,
        )
        .map_err(|err| {
            err.into_iter()
                .map(|se| format!("{:#?}", se))
                .collect::<Vec<String>>()
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_xml_invoice() {
        let config = Default::default();
        let result = validate_xml_invoice(
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
}
