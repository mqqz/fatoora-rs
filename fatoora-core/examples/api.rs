// --8<-- [start:example]
#[tokio::main]
pub async fn main() {
    use fatoora_core::api::{CsidCredentials, Compliance, ZatcaClient};
    use fatoora_core::config::{Config, EnvironmentType};
    use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

    // Doc example: build a client and prepare compliance request data.
    let signed_xml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
    let config = Config::new(EnvironmentType::NonProduction);
    let client = ZatcaClient::new(config).expect("create client");

    let xml = std::fs::read_to_string(&signed_xml_path).expect("read xml");
    let signed = parse_signed_invoice_xml(&xml).expect("parse signed invoice");
    let hash = signed.hash_base64().expect("compute hash");

    let ccsid = CsidCredentials::<Compliance>::new(
        EnvironmentType::NonProduction,
        Some(1234567890),
        "binary_security_token",
        "secret",
    );

    assert!(!hash.is_empty());
    let _ = (client, signed, ccsid);
    // let response = client.check_invoice_compliance(&signed, &ccsid).await?;
    // println!("{:?}", response.validation_results().status());
}
// --8<-- [end:example]
