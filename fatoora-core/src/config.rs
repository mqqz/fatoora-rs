//! Configuration and environment selection.
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}, str::FromStr};
use thiserror::Error;

/// ZATCA environment selection for API endpoints.
/// This determines which URL the API client will use and also is needed for the template format
/// used in CSR generation.
/// - NonProduction: This is what ZATCA refers to as the "Integration Sandbox".
/// - Simulation: This is the "Simulation Test Environment" provided by ZATCA which you need to
/// sign up for.
/// - Production: The live production environment.
/// # Examples
/// ```rust
/// use std::str::FromStr;
/// use fatoora_core::config::EnvironmentType;
///
/// let env = EnvironmentType::from_str("simulation")?;
/// assert_eq!(env, EnvironmentType::Simulation);
/// # Ok::<(), fatoora_core::EnvironmentParseError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvironmentType {
    NonProduction,
    Simulation,
    Production,
}

/// Error returned when parsing an [`EnvironmentType`] from a string.
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

/// Configuration for validation and API clients.
///
/// # Examples
/// ```rust
/// use fatoora_core::config::{Config, EnvironmentType};
///
/// let config = Config::new(EnvironmentType::NonProduction, "path/to/UBL-Invoice-2.1.xsd");
/// # let _ = config;
/// ```
#[derive(Debug)]
pub struct Config {
    env: EnvironmentType,
    xsd_ubl_path: PathBuf,
}

impl Config {
    pub fn new(env: EnvironmentType, xsd_ubl_path: impl Into<PathBuf>) -> Self {
        Self {
            env,
            xsd_ubl_path: xsd_ubl_path.into(),
        }
    }

    pub fn env(&self) -> EnvironmentType {
        self.env
    }

    pub fn xsd_ubl_path(&self) -> &Path {
        &self.xsd_ubl_path
    }
}

// static function to get default config
impl Default for Config {
    fn default() -> Self {
        Config {
            env: EnvironmentType::NonProduction,
            xsd_ubl_path: PathBuf::from(
                "./assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd",
            ),
        }
    }
}
