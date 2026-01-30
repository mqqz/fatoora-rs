# fatoora-rs

An unofficial open-source toolkit for ZATCA (Saudi Arabia) Phase 1 and 2 compliant e-invoicing. The core is written in Rust with a CLI and bindings for other languages.

!!! note
    This project is in active early development and the public API may evolve.

## Quick Start

=== "Rust"
    ```rust
    use fatoora_core::config::EnvironmentType;
    use fatoora_core::csr::{CsrProperties, SigningKey};

    let props_text = std::fs::read_to_string("csr.properties")?;
    let props = CsrProperties::from_properties_str(&props_text)?;
    let key = SigningKey::generate();
    let csr = props.build(&key, EnvironmentType::NonProduction)?;
    let csr_pem = csr.to_pem()?;
    let key_pem = key.to_pem()?;
    ```

=== "Python"
    ```python
    from fatoora.config import Environment
    from fatoora.csr import CsrProperties, SigningKey

    props = CsrProperties.parse_file("csr.properties")
    key = SigningKey.generate()
    csr = props.build(key, Environment.NON_PRODUCTION)
    csr_pem = csr.to_pem_base64()
    key_pem = key.to_pem()
    ```

=== "CLI"
    ```bash
    fatoora-rs-cli csr --csr-config csr.properties --generated-csr csr.pem --private-key key.pem --pem
    ```

## Where to Go Next
- [Getting Started](guides/getting-started.md)
- [CLI](guides/cli.md)
- [Python Bindings](guides/python-bindings.md)
- [Benchmarks](benchmarks.md)
- [Contributing](contributing.md)
