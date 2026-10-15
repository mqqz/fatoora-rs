---
title: Environment and Configuration Reference
description: Choose the ZATCA sandbox, simulation, or production environment. Find configuration values, constructors, defaults, and environment behavior for each language.
---

# Environment and configuration

Configuration selects the ZATCA API environment. Use the same environment for
CSR generation, credentials, and the client that sends requests.

## Environment values

| Environment | Purpose | API base URL |
| --- | --- | --- |
| Non-production | Integration sandbox for initial testing | `https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/` |
| Simulation | Testing the integration before production | `https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation/` |
| Production | Live invoice operations | `https://gw-fatoora.zatca.gov.sa/e-invoicing/core/` |

The environment also selects the CSR certificate-template extension. Choosing an
environment does not obtain credentials or establish that an invoice is accepted.
Clients reject credentials issued for a different environment before sending a request.

<span id="environment"></span>
<span id="config"></span>
<span id="from_str"></span>
<span id="as_str"></span>
<span id="endpoint_url"></span>
<span id="new"></span>
<span id="env"></span>
<span id="default"></span>

## Language reference

=== "Rust"
    Import `Config` and `EnvironmentType` from `fatoora_core::config`.

    | Operation | Returns | Behavior |
    | --- | --- | --- |
    | `Config::new(env: EnvironmentType)` | `Config` | Stores the selected environment. |
    | `Config::default()` | `Config` | Selects `EnvironmentType::NonProduction`. |
    | `config.env()` | `EnvironmentType` | Returns the stored value. |
    | `EnvironmentType::from_str(value: &str)` | `Result<EnvironmentType, EnvironmentParseError>` | Requires `std::str::FromStr` in scope. |
    | `env.as_str()` | `&'static str` | Returns the canonical string below. |
    | `env.endpoint_url()` | `&'static str` | Returns the base URL above. |

    The variants are `NonProduction`, `Simulation`, and `Production`. Parsing accepts
    `non_production`, `simulation`, and `production`, case-insensitively. It does not
    trim whitespace or accept `sandbox` as an alias. Canonical strings are lowercase.

=== "Python"
    Import `Config` and `Environment` from `fatoora`.

    | Operation | Returns | Behavior |
    | --- | --- | --- |
    | `Config(env=Environment.NON_PRODUCTION)` | `Config` | Creates configuration; defaults to non-production. |
    | `config.env()` | `Environment` | Returns the stored value. |
    | `Environment(value)` | `Environment` | Converts integer `0`, `1`, or `2`; invalid values raise `ValueError`. |
    | `env.value` | `int` | Returns the numeric value. |

    `Environment` is an integer enum: `NON_PRODUCTION = 0`, `SIMULATION = 1`,
    `PRODUCTION = 2`. It does not parse environment names. Configuration objects support
    `with` and `close()`; see [Python resource handling](bindings/python.md).

=== "JavaScript"
    Import `Config` from `fatoority`.

    | Operation | Returns | Behavior |
    | --- | --- | --- |
    | `Config.new_(env)` | `Config` | Pass integer `0`, `1`, or `2`. |
    | `config.env()` | `number` | Returns the stored environment. |

    Use `0` for non-production, `1` for simulation, `2` for production. There is no
    implicit default. Invalid environments throw an `Error` with a `BindingError` cause. See
    [JavaScript setup](bindings/javascript.md) for loading the package.

=== "C#"
    Use the `Fatoora` namespace.

    | Operation | Returns | Behavior |
    | --- | --- | --- |
    | `Config.New(byte env)` | `Config` | Pass `0`, `1`, or `2`. |
    | `config.Env()` | `byte` | Returns the stored environment. |

    Use `0` for non-production, `1` for simulation, `2` for production. There is no
    implicit default. Invalid environments throw `BindingErrorException`. Use `using` to
    dispose configuration when finished. See [C# setup](bindings/csharp.md).

=== "Kotlin"
    Import `com.fatoora.Config`.

    | Operation | Returns | Behavior |
    | --- | --- | --- |
    | `Config.create(env: Int)` | `Config` | Pass `0`, `1`, or `2`. |
    | `config.env()` | `Int` | Returns the stored environment. |

    Use `0` for non-production, `1` for simulation, `2` for production. There is no
    implicit default. Invalid values raise an exception. Use `.use { ... }` or `close()`
    for configuration objects. See [Kotlin setup](bindings/kotlin.md).

=== "Java"
    Import `com.fatoora.Config`.

    | Operation | Returns | Behavior |
    | --- | --- | --- |
    | `Config.create(int env)` | `Config` | Pass `0`, `1`, or `2`. |
    | `config.env()` | `int` | Returns the stored environment. |

    Use `0` for non-production, `1` for simulation, `2` for production. There is no
    implicit default. Invalid values raise an exception. Use try-with-resources or
    `close()` for configuration objects. See [Java setup](bindings/kotlin.md).

=== "C"
    Include `fatoora.h`. Pass `0` for non-production, `1` for simulation, or `2` for
    production. There is no implicit default; other values return an error.

    ```c
    FatooraStatus fatoora_config_new(int32_t env,
        FatooraConfig **out, FatooraError **error);
    FatooraStatus fatoora_config_env(const FatooraConfig *self,
        uint8_t *out, FatooraError **error);
    void fatoora_config_free(FatooraConfig *self);
    ```

    On `FATOORA_OK`, the constructor writes an owned configuration to `out` and the
    getter writes the environment number. Release configuration with
    `fatoora_config_free`. See [C error and ownership conventions](bindings/c.md).

## Related reference

- [CSR and private keys](csr.md)
- [ZATCA API client](api-client.md)
