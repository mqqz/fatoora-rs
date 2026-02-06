# Configuration

Environment selection used by the API client and validation helpers.

## Environment

??? note "Parse and inspect"
    Parse environment values and resolve API base URLs.

    === "{{ lang.rust }}"
        ```rust
        EnvironmentType::from_str(env: &str) -> Result<EnvironmentType, EnvironmentParseError>
        EnvironmentType::as_str(&self) -> &'static str
        EnvironmentType::endpoint_url(&self) -> &'static str
        ```

    === "{{ lang.python }}"
        ```python
        Environment
        ```

    === "{{ lang.c }}"
        ```c
        FfiEnvironment
        ```

    !!! info "Args"
        - `env`: non_production, simulation, or production.

    !!! info "Returns"
        - `EnvironmentType` / `Environment`: parsed environment.
        - `endpoint_url`: base URL for ZATCA API.

## Config

??? note "Create and read"
    Create config handles and read their environment.

    === "{{ lang.rust }}"
        ```rust
        Config::new(env: EnvironmentType) -> Config
        Config::env(&self) -> EnvironmentType
        Config::default() -> Config
        ```

    === "{{ lang.python }}"
        ```python
        Config(env: Environment = Environment.NON_PRODUCTION)
        Config.env_value() -> Environment
        Config.validate_xml(xml: str) -> bool
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiConfig fatoora_config_new(FfiEnvironment env);
        FfiResult_FfiEnvironment fatoora_config_env(FfiConfig* config);
        void fatoora_config_free(FfiConfig* config);
        ```

    !!! info "Args"
        - `env`: target environment.
        - `xml`: invoice XML string (Python convenience).

    !!! info "Returns"
        - `Config` / `FfiConfig`: environment-aware handle.
        - `Environment`: environment value from the handle.

