# Configuration

Environment selection used by the API client and validation helpers.

## Symbols

=== "Rust"
    - `EnvironmentType::from_str(env: &str) -> Result<EnvironmentType, EnvironmentParseError>` — parse `non_production`, `simulation`, `production`.
    - `EnvironmentType::as_str(&self) -> &'static str` — lowercase string form.
    - `EnvironmentType::endpoint_url(&self) -> &'static str` — base URL for ZATCA API.
    - `Config::new(env: EnvironmentType) -> Config` — construct config for an environment.
    - `Config::env(&self) -> EnvironmentType` — read the environment.
    - `Config::default() -> Config` — defaults to `NonProduction`.

=== "Python"
    - `Environment` — enum with `NON_PRODUCTION`, `SIMULATION`, `PRODUCTION`.
    - `Config(env: Environment = Environment.NON_PRODUCTION)` — create config handle.
    - `Config.env_value() -> Environment` — read environment from FFI handle.
    - `Config.validate_xml(xml: str) -> bool` — convenience wrapper for XML validation.

=== "C (FFI)"
    - `FfiEnvironment` — enum for environments.
    - `fatoora_config_new(env: FfiEnvironment) -> FfiResult_FfiConfig` — allocate config.
    - `fatoora_config_env(config: FfiConfig*) -> FfiResult_FfiEnvironment` — read environment.
    - `fatoora_config_free(config: FfiConfig*) -> void` — release config.

## Behavior
- The config only holds the environment. XML validation always uses the bundled XSD in
  `fatoora-core/assets` (see `invoice-validation` and `xml-and-schemas`).

See also: [Getting Started Guide](../guides/getting-started.md)
