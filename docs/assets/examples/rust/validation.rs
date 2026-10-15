use fatoora_core::config::{Config, EnvironmentType};
use fatoora_core::invoice::validation::{
    validate_xml_invoice_from_str, validate_zatca_invoice_from_str, ZatcaValidationOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new(EnvironmentType::NonProduction);
    let xml = std::fs::read_to_string("invoice.xml")?;
    if std::env::args().any(|arg| arg == "--zatca") {
        let options = ZatcaValidationOptions {
            previous_invoice_hash: Some(std::fs::read_to_string("previous-hash.txt")?.trim().into()),
            ..Default::default()
        };
        let report = validate_zatca_invoice_from_str(&xml, &config, &options)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !report.is_valid() { std::process::exit(1); }
    } else {
        validate_xml_invoice_from_str(&xml, &config)?;
        println!("XSD valid");
    }
    Ok(())
}
