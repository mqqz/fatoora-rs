use fatoora_core::api::{CsidCredentials, Production, ZatcaClient};
use fatoora_core::config::{Config, EnvironmentType};
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let environment = EnvironmentType::NonProduction;
    let token = std::env::var("ZATCA_TOKEN")?;
    let secret = std::env::var("ZATCA_SECRET")?;
    let client = ZatcaClient::new(Config::new(environment))?;
    let credentials = CsidCredentials::<Production>::new(environment, None, token, secret);
    let xml = std::fs::read_to_string("signed.xml")?;
    let invoice = parse_signed_invoice_xml(&xml)?;
    let response = client.report_simplified_invoice(&invoice, &credentials, false, Some("en")).await?;
    response.ensure_accepted()?;
    println!("Invoice reporting accepted");
    Ok(())
}
