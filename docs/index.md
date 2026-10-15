# fatoority

An unofficial open-source toolkit for ZATCA (Saudi Arabia) Phase 1 and 2 compliant e-invoicing. The core is written in Rust with a CLI and bindings for other languages.

!!! note
    This project is in active early development and the public API may evolve.

## Why 

This library was born out of the frustration involved in working with the ZATCA ecosystem; The official documentation is fragmented, too high-level at best or just totally vague. The official CLI is slow, restrictive, and difficult to integrate into real-world workflow, and existing third-party libraries tend to be incomplete, poorly documented, or built around narrow assumptions that do not generalise well.

`fatoority` aims to remove this overhead by handling ZATCA specific details in a predictable and reliable way. By abstracting away compliance quirks and low-level details, development effort can stay focused on business logic and product concerns, where it actually matters.

## Features

- ZATCA phase 1 + 2 compliance (incl. all invoice sub/types)
- Fast and efficient
- Well-documented
- Easy-to-use


## Quick Start

There are two main ways to interact with `fatoority`. Either through:

- **The Command Line Interaface (CLI)**:

This CLI aims to be a *lighter, efficient and ergonomic* replacement to the official [ZATCA SDK](https://sandbox.zatca.gov.sa/downloadSDK) CLI tool.

- **Code Libraries**:

The main core library (`fatoora-core`) is written in Rust with a C FFI that allows interopability with many languages:

    - Rust (using the `fatoora-core` crate)

    - C/C++ (directly through the FFI shared library)

    - Python (wrapper library over the FFI)

    - JavaScript / TypeScript (WebAssembly with async fetch)

    - C# / .NET 8 (NuGet with native runtime assets)

## Installation

=== "Rust"
    ```bash
    cargo add fatoora-core
    ```

=== "Python"
    ```bash
    pip install fatoority
    ```

=== "JavaScript / TypeScript"
    ```sh
    npm install fatoority
    ```
    See the [JS/TS reference](reference/bindings/javascript.md) for source builds,
    browser deployment, async API calls and package sizes.

=== "C# / .NET"
    Build a local NuGet package from a source checkout:
    ```sh
    python3 scripts/package_dotnet.py --output-dir dist/dotnet
    ```
    Install it in your application's project:
    ```sh
    dotnet add package Fatoority --version 0.4.3 --source /absolute/path/to/dist/dotnet
    ```
    See the [C# / .NET reference](reference/bindings/csharp.md) for requirements,
    native platforms, and ownership rules.

=== "C (FFI)"
    Download the precompiled ffi library and headers for your platform from [github releases](https://github.com/mqqz/fatoority/releases)
    and use the [C API](development/c-api.md) for plain strings,
    named-field options, and shared error handling.

=== "CLI"
    You can either install the binary using `cargo install`:
    ```bash
    cargo install fatoora-cli
    ```
    Or alternatively grab the precompiled binary for your platform from [github releases](https://github.com/mqqz/fatoority/releases)


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

    props = CsrProperties.parse_csr_config_file("csr.properties")
    key = SigningKey.generate()
    csr = props.build(key, Environment.NON_PRODUCTION)
    csr_pem = csr.to_pem_base64()
    key_pem = key.to_pem()
    ```

=== "C# / .NET"
    ```csharp
    using Fatoora;

    using var properties = CsrProperties.ParseCsrConfigFile("csr.properties");
    using var key = SigningKey.Generate();
    using var csr = properties.Build(key, 0); // Nonproduction.
    string csrPem = csr.ToPem();
    string keyPem = key.ToPem();
    ```

=== "CLI"
    ```bash
    fatoora csr --csr-config csr.properties --generated-csr csr.pem --private-key key.pem --pem
    ```

## Runtime boundaries

Local validation covers UBL schemas, ZATCA rules and applicable signature/QR checks.
It does not establish gateway acceptance or certificate issuer trust.
Browser API calls depend on gateway CORS; server-side Node uses its own fetch transport.
JS objects belong to their WASM instance and cannot be shared between workers.

## Where to Go Next
- [CLI](guides/cli.md)
- [JavaScript / TypeScript](reference/bindings/javascript.md)
- [Python Bindings](reference/bindings/python.md)
- [C# / .NET](reference/bindings/csharp.md)
- [Benchmarks](benchmarks.md)
- [Contributing](contributing.md)
