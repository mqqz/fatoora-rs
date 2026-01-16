use serde::{Deserialize, Serialize};
use std::{path::Path, str::FromStr};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvironmentType {
    NonProduction,
    Simulation,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EnvironmentParseError {
    #[error("invalid environment type: {input}")]
    Invalid { input: String },
}

impl FromStr for EnvironmentType {
    type Err = EnvironmentParseError;
    fn from_str(env: &str) -> Result<EnvironmentType, EnvironmentParseError> {
        match env.to_ascii_lowercase().as_str() {
            "non_production" => Ok(EnvironmentType::NonProduction),
            "simulation" => Ok(EnvironmentType::Simulation),
            "production" => Ok(EnvironmentType::Production),
            _ => Err(EnvironmentParseError::Invalid {
                input: env.to_string(),
            }),
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

    pub fn endpoint_url(&self) -> &'static str {
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
    env: EnvironmentType,
    xsd_ubl_path: &'static Path,
}

impl Config {
    pub fn new(env: EnvironmentType, xsd_ubl_path: &'static Path) -> Self {
        Self { env, xsd_ubl_path }
    }

    pub fn env(&self) -> EnvironmentType {
        self.env
    }

    pub fn xsd_ubl_path(&self) -> &Path {
        self.xsd_ubl_path
    }
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
