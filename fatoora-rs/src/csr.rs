use std::{fs::File, io::BufReader, path};

use anyhow::{Ok, Result};
use java_properties::read;
use regex::Regex;
use std::sync::LazyLock;

// 1-(.+)\\|2-(.+)\\|3-(.+)
static SERIAL_NUMBER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^1-(.+)\\|2-(.+)\\|3-(.+)$").unwrap()
});

static INVOICE_TYPE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^1-(.+)\\|2-(.+)\\|3-(.+))$").unwrap()
});


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

impl CsrProperties{
    pub fn new(
        common_name: String,
        serial_number: String,
        organization_identifier: String,
        organization_unit_name: String,
        organization_name: String,
        country_name: String,
        invoice_type: String,
        location_address: String,
        industry_business_category: String,
    ) -> Self {

        // trim all and check not empty
        for s in [&common_name, &serial_number, &organization_identifier, &organization_unit_name, &organization_name, &country_name, &invoice_type, &location_address, &industry_business_category] {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                panic!("CsrProperties: field cannot be empty");
            }
        }  

        Self {
            common_name,
            serial_number,
            organization_identifier,
            organization_unit_name,
            organization_name,
            country_name,
            invoice_type,
            location_address,
            industry_business_category,
        }
    }
}

pub fn generate_csr_from_config(
    config_path: &str,
    private_key_path: Option<&str>,
    generated_csr_path: Option<&str>,
    to_pem: bool,
) -> Result<String> {
    // Parse properties file
    let csr_config = parse_csr_config(config_path)?;
    // TODO: Generate secp256k1 key

    // TODO: Generate CSR in base64 or PEM
    Ok("PLACEHOLDER_CSR".into())
}

fn parse_csr_config(csr_path: &str) -> Result<CsrProperties> {
    let file = File::open(csr_path)?;
    let dst_map = read(BufReader::new(file))?;

    Ok(CsrProperties {
        common_name: dst_map
            .get("csr.common.name")
            .ok_or_else(|| anyhow::anyhow!("common_name not found"))?
            .to_string(),
        serial_number: dst_map
            .get("csr.serial.number")
            .ok_or_else(|| anyhow::anyhow!("serial_number not found"))?
            .to_string(),
        organization_identifier: dst_map
            .get("csr.organization.identifier")
            .ok_or_else(|| anyhow::anyhow!("organizational_identifier not found"))?
            .to_string(),
        organization_unit_name: dst_map
            .get("csr.organization.unit.name")
            .ok_or_else(|| anyhow::anyhow!("organizational_unit_name not found"))?
            .to_string(),
        organization_name: dst_map
            .get("csr.organization.name")
            .ok_or_else(|| anyhow::anyhow!("organization_name not found"))?
            .to_string(),
        country_name: dst_map
            .get("csr.country.name")
            .ok_or_else(|| anyhow::anyhow!("country_name not found"))?
            .to_string(),
        invoice_type: dst_map
            .get("csr.invoice.type")
            .ok_or_else(|| anyhow::anyhow!("invoice_type not found"))?
            .to_string(),
        location_address: dst_map
            .get("csr.location.address")
            .ok_or_else(|| anyhow::anyhow!("location_address not found"))?
            .to_string(),
        industry_business_category: dst_map
            .get("csr.industry.business.category")
            .ok_or_else(|| anyhow::anyhow!("industry_business_category not found"))?
            .to_string(),
    })
}

mod tests {
    use super::*;

    #[test]
    fn test_parse_csr_config() {
        let csr_config = parse_csr_config("assets/csr-configs/csr-config-example-EN.properties").unwrap();
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
