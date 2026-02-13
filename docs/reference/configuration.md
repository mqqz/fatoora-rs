# Configuration

Environment selection used by the API client and validation helpers.

## EnvironmentType / Environment / FfiEnvironment

### from_str / parse

??? note "Parse environment"
    Convert a string value to an environment enum.

    === "{{ lang.rust }}"
        ```rust
        EnvironmentType::from_str(env: &str) -> Result<EnvironmentType, EnvironmentParseError>
        ```

    === "{{ lang.python }}"
        ```python
        Environment(value: str) -> Environment
        ```

    === "{{ lang.c }}"
        ```c
        /* parse is not exposed in C; use FfiEnvironment enum constants directly */
        ```

    !!! info "Args"
        - `env` / `value` (`str`): `"non_production"`, `"simulation"`, or `"production"`.

    !!! info "Returns"
        - Rust: `Result<EnvironmentType, EnvironmentParseError>`.
        - Python: `Environment`.
        - C: not applicable.

### as_str / value

??? note "Get canonical string"
    Return the canonical string value of the environment.

    === "{{ lang.rust }}"
        ```rust
        EnvironmentType::as_str(&self) -> &'static str
        ```

    === "{{ lang.python }}"
        ```python
        Environment.value: str
        ```

    === "{{ lang.c }}"
        ```c
        /* not exposed; use enum value directly */
        ```

    !!! info "Returns"
        - Rust: `&'static str`.
        - Python: `str`.
        - C: not applicable.

### endpoint_url

??? note "Resolve API base URL"
    Return the ZATCA API base URL for the selected environment.

    === "{{ lang.rust }}"
        ```rust
        EnvironmentType::endpoint_url(&self) -> &'static str
        ```

    === "{{ lang.python }}"
        ```python
        # not directly exposed
        ```

    === "{{ lang.c }}"
        ```c
        /* not exposed */
        ```

    !!! info "Returns"
        - Rust: `&'static str`.
        - Python: not exposed.
        - C: not exposed.

## Config

### new

??? note "Create config"
    Create an environment-aware config handle.

    === "{{ lang.rust }}"
        ```rust
        Config::new(env: EnvironmentType) -> Config
        ```

    === "{{ lang.python }}"
        ```python
        Config(env: Environment = Environment.NON_PRODUCTION)
        ```

    === "{{ lang.c }}"
        ```c
        FfiConfig* fatoora_config_new(FfiEnvironment env);
        ```

    !!! info "Args"
        - `env` (`EnvironmentType`/`Environment`/`FfiEnvironment`): target environment.

    !!! info "Returns"
        - Rust: `Config`.
        - Python: `Config`.
        - C: `FfiConfig*`.

### env / env_value

??? note "Read config environment"
    Return the environment value stored in a config.

    === "{{ lang.rust }}"
        ```rust
        Config::env(&self) -> EnvironmentType
        ```

    === "{{ lang.python }}"
        ```python
        Config.env_value() -> Environment
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiEnvironment fatoora_config_env(FfiConfig* config);
        ```

    !!! info "Args"
        - C only: `config` (`FfiConfig*`).

    !!! info "Returns"
        - Rust: `EnvironmentType`.
        - Python: `Environment`.
        - C: `FfiResult_FfiEnvironment`.

### default

??? note "Default config"
    Create a default config using non-production environment.

    === "{{ lang.rust }}"
        ```rust
        Config::default() -> Config
        ```

    === "{{ lang.python }}"
        ```python
        Config() -> Config
        ```

    === "{{ lang.c }}"
        ```c
        /* call fatoora_config_new(FfiEnvironment_NonProduction) */
        ```

    !!! info "Returns"
        - Rust: `Config`.
        - Python: `Config`.
        - C: use `fatoora_config_new(...)`.

### validate_xml (Python convenience)

??? note "Validate XML with config"
    Python convenience wrapper for XML validation.

    === "{{ lang.rust }}"
        ```rust
        // use validate_xml_invoice_from_str(xml: &str, config: &Config)
        ```

    === "{{ lang.python }}"
        ```python
        Config.validate_xml(xml: str) -> bool
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_validate_xml_str(FfiConfig* config, const char* xml);
        ```

    !!! info "Args"
        - `xml` (`str` / `const char*`): invoice XML content.
        - `config` (`&Config` / `FfiConfig*`): validation context.

    !!! info "Returns"
        - Rust: `Result<(), XmlValidationError>` via standalone function.
        - Python: `bool` (raises on failure).
        - C: `FfiResult_bool`.
