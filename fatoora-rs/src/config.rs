#[derive(Debug)]
pub enum EnvironmentType {
    NonProduction,
    Simulation,
    Production,
}

impl EnvironmentType {
    pub fn from_str(env: &str) -> Result<EnvironmentType, anyhow::Error> {
        match env.to_ascii_lowercase().as_str() {
            "non_production" => Ok(EnvironmentType::NonProduction),
            "simulation" => Ok(EnvironmentType::Simulation),
            "production" => Ok(EnvironmentType::Production),
            _ => Err(anyhow::anyhow!("Invalid environment type")),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub env: EnvironmentType,
}

// static function to get default config
impl Default for Config {
    fn default() -> Self {
        Config {
            env: EnvironmentType::NonProduction,
        }
    }
}
