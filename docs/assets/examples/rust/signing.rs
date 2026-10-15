use fatoora_core::invoice::sign::InvoiceSigner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let xml = std::fs::read_to_string("invoice.xml")?;
    let certificate = std::fs::read_to_string("certificate.pem")?;
    let key = std::fs::read_to_string("private-key.pem")?;
    let signer = InvoiceSigner::from_pem(&certificate, &key)?;
    std::fs::write("signed.xml", signer.sign_xml(&xml)?)?;
    println!("Saved signed.xml");
    Ok(())
}
