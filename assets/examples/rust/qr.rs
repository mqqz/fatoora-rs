use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let xml = std::fs::read_to_string("signed.xml")?;
    let invoice = parse_signed_invoice_xml(&xml)?;
    std::fs::write("qr.txt", invoice.qr_code())?;
    println!("{}", invoice.qr_code());
    Ok(())
}
