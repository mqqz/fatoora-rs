use fatoora_core::config::{Config, EnvironmentType};
use fatoora_core::{Error, ErrorKind};

#[test]
fn environment_selection_never_defaults_to_production() {
    assert_eq!(Config::default().env(), EnvironmentType::NonProduction);
    for (input, environment, path) in [
        (
            "NON_PRODUCTION",
            EnvironmentType::NonProduction,
            "developer-portal",
        ),
        ("Simulation", EnvironmentType::Simulation, "simulation"),
        ("production", EnvironmentType::Production, "core"),
    ] {
        let parsed: EnvironmentType = input.parse().unwrap();
        assert_eq!(parsed, environment);
        assert_eq!(parsed.as_str(), input.to_ascii_lowercase());
        assert_eq!(
            Config::new(parsed).env().endpoint_url(),
            format!("https://gw-fatoora.zatca.gov.sa/e-invoicing/{path}/")
        );
    }
    for input in ["", "prod", " production", "production\0", "simulatiоn"] {
        let error: Error = input.parse::<EnvironmentType>().unwrap_err().into();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let details: serde_json::Value = serde_json::from_str(&error.details_json()).unwrap();
        assert_eq!(details["type"], "invalid_environment");
        assert_eq!(details["value"], input);
    }
}
