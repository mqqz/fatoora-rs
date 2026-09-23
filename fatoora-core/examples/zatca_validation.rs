use fatoora_core::{
    config::Config,
    invoice::validation::{ZatcaValidationOptions, validate_zatca_invoice_from_str},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let xml = include_str!("../tests/fixtures/sdk-parity/cases/standard-invoice/input.xml");
    // Use the actual predecessor digest for every invoice after the first.
    let options = ZatcaValidationOptions {
        previous_invoice_hash: Some("NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==".into()),
        evaluated_at: Some("2026-09-23T12:00:00+03:00".parse()?),
    };
    let report = validate_zatca_invoice_from_str(xml, &Config::default(), &options)?;
    assert!(report.is_valid());
    println!("{}", serde_json::to_string_pretty(&report)?);
    let rejected = validate_zatca_invoice_from_str("<wrong/>", &Config::default(), &options)?;
    assert!(rejected.has_errors());
    assert!(!rejected.is_valid());
    Ok(())
}
