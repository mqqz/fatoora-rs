# fatoora-rs

An unofficial open-source toolkit for ZATCA (Saudi Arabia) Phase 1 and 2 compliant e-invoicing. The core is written in Rust with a CLI and bindings for other languages.

!!! note
    This project is in active early development and the public API may evolve.

## Why 

This library was born out of the frustration involved in working with the ZATCA ecosystem; The official documentation is fragmented, too high-level at best or just totally vague. The official CLI is slow, restrictive, and difficult to integrate into real-world workflow, and existing third-party libraries tend to be incomplete, poorly documented, or built around narrow assumptions that do not generalise well.

`fatoora-rs` aims to remove this overhead by handling ZATCA specific details in a predictable and reliable way. By abstracting away compliance quirks and low-level details, development effort can stay focused on business logic and product concerns, where it actually matters.

## Features

- ZATCA phase 1 + 2 compliance (incl. all invoice sub/types)
- Fast and efficient
- Well-documented
- Easy-to-use


## Quick Start

There are two main ways to interact with `fatoora-rs`. Either through:

- **The Command Line Interaface (CLI)**:
This CLI aims to be a *lighter, efficient and ergonomic* replacement to the official [ZATCA SDK](https://sandbox.zatca.gov.sa/downloadSDK) CLI tool.

- **Code Libraries**:
The main core library (`fatoora-core`) is written in Rust with a C FFI that allows interopability with many languages:
    - Rust (using the `fatoora-core` crate)
    - C/C++ (directly through the FFI shared library)
    - Python (wrapper library over the FFI)

## Installation

=== "Rust"
    ```bash
    cargo add fatoora-core
    ```

=== "Python"
    ```bash
    pip install fatoora-rs
    ```

=== "C (FFI)"
    Download the precompiled ffi library and headers for your platform from [github releases](https://github.com/mqqz/fatoora-rs/releases)

=== "CLI"
    You can either install the binary using `cargo install`:
    ```bash
    cargo install fatoora-rs-cli
    ```
    Or alternatively grab the precompiled binary for your platform from [github releases](https://github.com/mqqz/fatoora-rs/releases)


## Basic Usage

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

## Current Limitations
    - Multithreaded usage is unsupported/untested, so use at your own risk
    - Only tested on sandbox, due to the difficulty of accessing the production environment
    - Test suite needs more edge cases
    - Invoice valdiation only covers the basic UBL format, no specific ZATCA/KSA rules yet.

## Where to Go Next
- [Getting Started](guides/getting-started.md)
- [CLI](guides/cli.md)
- [Python Bindings](guides/python-bindings.md)
- [Benchmarks](benchmarks.md)
- [Contributing](contributing.md)
