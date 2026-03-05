# Configuration

There are three main "environments" which are required to determine which ZATCA API endpoint to use.
Additionally, the type of environment changes the signing/validation process slightly.

- "Non-Production"
      Sometimes also called the "Sandbox". It's open to anyone to use without registration for
      initial testing. It's a dummy environment with mainly hardcoded values and responses. For 
      instance, the OTP "123345" is always considered valid.

      Endpoint: ["https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/"]

- "Simulation":
      The simulation environment requires registration at the developer portal. It's also used for
      testing only.

      Endpoint: ["https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation/"]

- "Production":
      This is the real deal environment for in-production systems where real invoices are to be 
      reported.

      Endpoint: ["https://gw-fatoora.zatca.gov.sa/e-invoicing/core/"]

## Environment

### `from_str`

???+ note "Parse environment"
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

### `as_str`

???+ note "Get canonical string"
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

### `endpoint_url`

???+ note "Resolve API base URL"
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

## Config

### `new`

???+ note "Create config"
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

### `env`

???+ note "Read config environment"
    Return the environment value stored in a config.

    === "{{ lang.rust }}"
        ```rust
        Config::env(&self) -> EnvironmentType
        ```

    === "{{ lang.python }}"
        ```python
        Config.env() -> Environment
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiEnvironment fatoora_config_env(FfiConfig* config);
        ```

### `default`

???+ note "Default config"
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
