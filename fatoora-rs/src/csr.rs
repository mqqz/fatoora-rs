use std::{fs::File, io::BufReader, path};

use java_properties::read;

use fatoora_derive::Validate;

#[derive(Validate, Debug)]
#[validate(non_empty, no_special_chars)]
pub struct CsrProperties {
    common_name: String,
    serial_number: String,
    organization_identifier: String,
    organization_unit_name: String,
    organization_name: String,
    country_name: String,
    invoice_type: String,
    location_address: String,
    industry_business_category: String,
}


fn parse_csr_config(csr_path: &str) -> Result<CsrProperties, anyhow::Error> {
    let file = File::open(csr_path)?;
    let dst_map = read(BufReader::new(file))?;

    let csr = CsrProperties::new(
        dst_map.get("csr.common.name")
            .ok_or_else(|| anyhow::anyhow!("common_name not found"))?
            .to_string(),

        dst_map.get("csr.serial.number")
            .ok_or_else(|| anyhow::anyhow!("serial_number not found"))?
            .to_string(),

        dst_map.get("csr.organization.identifier")
            .ok_or_else(|| anyhow::anyhow!("organizational_identifier not found"))?
            .to_string(),

        dst_map.get("csr.organization.unit.name")
            .ok_or_else(|| anyhow::anyhow!("organization_unit_name not found"))?
            .to_string(),

        dst_map.get("csr.organization.name")
            .ok_or_else(|| anyhow::anyhow!("organization_name not found"))?
            .to_string(),

        dst_map.get("csr.country.name")
            .ok_or_else(|| anyhow::anyhow!("country_name not found"))?
            .to_string(),

        dst_map.get("csr.invoice.type")
            .ok_or_else(|| anyhow::anyhow!("invoice_type not found"))?
            .to_string(),

        dst_map.get("csr.location.address")
            .ok_or_else(|| anyhow::anyhow!("location_address not found"))?
            .to_string(),

        dst_map.get("csr.industry.business.category")
            .ok_or_else(|| anyhow::anyhow!("industry_business_category not found"))?
            .to_string(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    Ok(csr)
}


mod tests {
    use super::*;

    #[test]
    fn test_parse_csr_config() {
        let csr_config = parse_csr_config("../assets/csr-configs/csr-config-example-EN.properties").unwrap();
        assert_eq!(csr_config.common_name, "TST-886431145-399999999900003");
        assert_eq!(csr_config.serial_number, "1-TST|2-TST|3-ed22f1d8-e6a2-1118-9b58-d9a8f11e445f");
        assert_eq!(csr_config.organization_identifier, "399999999900003");
        assert_eq!(csr_config.organization_unit_name, "Riyadh Branch");
        assert_eq!(csr_config.organization_name, "Maximum Speed Tech Supply LTD");
        assert_eq!(csr_config.country_name, "SA");
        assert_eq!(csr_config.invoice_type, "1100");
        assert_eq!(csr_config.location_address, "RRRD2929");
        assert_eq!(csr_config.industry_business_category, "Supply activities");
    }
}
