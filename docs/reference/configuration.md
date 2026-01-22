# Configuration

Configuration types and environment selection.

## Types
- `EnvironmentType` selects the ZATCA environment (`NonProduction`, `Simulation`, `Production`) and
  provides `as_str()` and `endpoint_url()` helpers. It also controls CSR template selection.
- `EnvironmentParseError` is returned by `EnvironmentType::from_str` for invalid inputs.
- `Config` stores the environment and the UBL XSD path used by XML validation and API requests.
  Construct with `Config::new(env)` or `Config::with_xsd_path(env, path)`.

## Behavior
- `Config::new` and `Config::default` use the bundled UBL schema at
  `assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd`.
- Use `Config::with_xsd_path` to point validation to a custom schema file.

See also: [Getting Started Guide](../guides/getting-started.md)
