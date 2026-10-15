use fatoora_core::config::EnvironmentType;
use fatoora_core::csr::{CsrProperties, SigningKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string("csr.properties")?;
    let properties = CsrProperties::from_properties_str(&text)?;
    let key = SigningKey::generate();
    let csr = properties.build(&key, EnvironmentType::NonProduction)?;
    std::fs::write("csr.pem", csr.to_pem()?)?;
    std::fs::write("key.pem", key.to_pem()?)?;
    println!("Saved csr.pem and key.pem");
    Ok(())
}
