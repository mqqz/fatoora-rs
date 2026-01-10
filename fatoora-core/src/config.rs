use serde::{Deserialize, Serialize};
use std::{path::Path, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvironmentType {
    NonProduction,
    Simulation,
    Production,
}

impl FromStr for EnvironmentType {
    type Err = anyhow::Error;
    fn from_str(env: &str) -> Result<EnvironmentType, anyhow::Error> {
        match env.to_ascii_lowercase().as_str() {
            "non_production" => Ok(EnvironmentType::NonProduction),
            "simulation" => Ok(EnvironmentType::Simulation),
            "production" => Ok(EnvironmentType::Production),
            _ => Err(anyhow::anyhow!("Invalid environment type")), // TODO standardise error
                                                                   // handling
        }
    }
}

impl EnvironmentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnvironmentType::NonProduction => "non_production",
            EnvironmentType::Simulation => "simulation",
            EnvironmentType::Production => "production",
        }
    }

    pub fn get_endpoint_url(&self) -> &'static str {
        match self {
            EnvironmentType::NonProduction => {
                "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/"
            }
            EnvironmentType::Simulation => {
                "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation/"
            }
            EnvironmentType::Production => "https://gw-fatoora.zatca.gov.sa/e-invoicing/core/",
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub env: EnvironmentType,
    pub xsd_ubl_path: &'static Path,
}

// static function to get default config
impl Default for Config {
    fn default() -> Self {
        Config {
            env: EnvironmentType::NonProduction,
            xsd_ubl_path: Path::new("./assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd"),
        }
    }
}
