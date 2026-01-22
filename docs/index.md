# fatoora-rs

An unofficial open-source toolkit for ZATCA (Saudi Arabia) Phase 1 and 2 compliant e-invoicing. The core is written in Rust with a CLI and bindings for other languages.

!!! note
    This project is in active early development and the public API may evolve.

## Quick Start

=== "Rust"
    ```rust
    use fatoora_core::config::EnvironmentType;
    use fatoora_core::csr::CsrProperties;

    let props = CsrProperties::parse_csr_config("csr.properties".as_ref())?;
    let (csr, key) = props.build_with_rng(EnvironmentType::NonProduction)?;
    let csr_pem = csr.to_pem(Default::default())?;
    let key_pem = key.to_pkcs8_pem(Default::default())?;
    ```

=== "Python"
    ```python
    from fatoora.config import Environment
    from fatoora.csr import CsrProperties

    props = CsrProperties.parse("csr.properties")
    bundle = props.build_with_rng(Environment.NON_PRODUCTION)
    csr_pem = bundle.csr.to_pem_base64()
    key_pem = bundle.key.to_pem()
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
