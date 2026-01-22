
# `fatoora-rs`
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![codecov](https://codecov.io/gh/mqqz/fatoora-rs/graph/badge.svg?token=JRI6609XU6)](https://codecov.io/gh/mqqz/fatoora-rs) 
[![Crates.io Version](https://img.shields.io/crates/v/fatoora-core?logo=rust&label=fatoora-core)](https://crates.io/crates/fatoora-core)
[![Crates.io Version](https://img.shields.io/crates/v/fatoora-rs-cli?logo=rust&label=fatoora-rs-cli)](https://crates.io/crates/fatoora-rs-cli)
[![Crates.io Version](https://img.shields.io/crates/v/fatoora-derive?logo=rust&label=fatoora-derive)](https://crates.io/crates/fatoora-derive)
[![PyPi Version](https://img.shields.io/pypi/v/fatoora-rs?logo=python)](https://pypi.org/project/fatoora-rs/)

An *unofficial* open-source toolkit for everything you'd need for ZATCA (Zakat, Tax and Customs Authority of Saudi Arabia) Phase 1 and 2 compliant e-invoicing 

...with bindings and support for many programming languages (so far only C/C++ and Python).

...*and also built in Rust btw*

> `fatoora-rs` is in active early development. While the core functionality is usable, the public API is still evolving and may change as the project matures.
> We strive to maintain good test coverage and stability, but users should be aware that some rough edges may remain. 
> Feedback and contributions are especially welcome at this stage. 

**Disclaimer**:
`fatoora-rs` is not affiliated, associated, authorized, endorsed by, or in any way officially connected with ZATCA (Zakat, Tax and Customs Authority), or any of its subsidiaries or its affiliates. The official ZATCA website can be found at https://zatca.gov.sa.

## Documentation
- Rust API: [docs.rs](https://docs.rs/fatoora-core/latest/fatoora_core/)
- Project docs: see `docs/` (MkDocs site)

## Features

Everything done by the official [ZATCA SDK](https://sandbox.zatca.gov.sa/downloadSDK) 
- CSR Generation
- Invoice Signing (All invoice types)
- Validation (UBL only for now)
- QR Generation
- API Requests

*But we do it faster and better* e.g. ~190x faster invoice hashing than ZATCA's SDK (see [`bench/`](https://github.com/mqqz/fatoora-rs/blob/main/bench/cli/results/hash_bench.md))

## Dependencies
XML parsing/manipulation is done internally with `libxml2`, so you might need to install it if you haven't already. See [here](https://github.com/KWARC/rust-libxml?tab=readme-ov-file#installation-prerequisites) for relevant instructions.

C headers are generated in `fatoora-ffi/include/`, with grouped headers under `fatoora/` (e.g., `fatoora/config.h`).

## Installation
The Rust library can be added with `cargo add fatoora-core`.

The cli tool can also be installed with `cargo`: 
```
cargo install fatoora-rs-cli
```

Python bindings:
```
pip install fatoora-rs
```
Python modules mirror the Rust core layout (e.g., `fatoora.config`, `fatoora.csr`, `fatoora.invoice`, `fatoora.sign`).

## Usage/Examples

<details>
<summary>CSR Generation</summary>

Rust
```rust
use fatoora_core::config::EnvironmentType;
use fatoora_core::csr::CsrProperties;

let props_text = std::fs::read_to_string("csr.properties")?;
let props = CsrProperties::from_properties_str(&props_text)?;
let (csr, key) = props.build_with_rng(EnvironmentType::NonProduction)?;
let csr_pem = csr.to_pem(Default::default())?;
let key_pem = key.to_pkcs8_pem(Default::default())?;
```

Python
```python
from fatoora.config import Environment
from fatoora.csr import CsrProperties

props = CsrProperties.parse("csr.properties")
bundle = props.build_with_rng(Environment.NON_PRODUCTION)
csr_pem = bundle.csr.to_pem_base64()
key_pem = bundle.key.to_pem()
```

CLI
```bash
fatoora-rs-cli csr --csr-config csr.properties --generated-csr csr.pem --private-key key.pem --pem
```
</details>

<details>
<summary>Invoice Signing</summary>

Rust
```rust
use fatoora_core::invoice::sign::InvoiceSigner;

let cert_pem = std::fs::read_to_string("cert.pem")?;
let key_pem = std::fs::read_to_string("key.pem")?;
let signer = InvoiceSigner::from_pem(cert_pem.trim(), key_pem.trim())?;
let xml = std::fs::read_to_string("invoice.xml")?;
let signed_xml = signer.sign_xml(&xml)?;
```

CLI
```bash
fatoora-rs-cli sign --invoice invoice.xml --cert cert.pem --key key.pem --signed-invoice signed.xml
```
</details>

<details>
<summary>Validation</summary>

Rust
```rust
use fatoora_core::config::Config;
use fatoora_core::invoice::validation::validate_xml_invoice_from_str;

let config = Config::new(fatoora_core::config::EnvironmentType::NonProduction);
let xml = std::fs::read_to_string("invoice.xml")?;
validate_xml_invoice_from_str(&xml, &config)?;
```

CLI
```bash
fatoora-rs-cli validate --invoice invoice.xml --xsd-path assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd
```
</details>

<details>
<summary>QR Extraction</summary>

Rust
```rust
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

let xml = std::fs::read_to_string("signed.xml")?;
let signed = parse_signed_invoice_xml(&xml)?;
let qr = signed.qr_code();
```

CLI
```bash
fatoora-rs-cli qr --invoice signed.xml
```
</details>

<details>
<summary>Invoice Hash</summary>

Rust
```rust
use fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml;

let xml = std::fs::read_to_string("invoice.xml")?;
let invoice = parse_finalized_invoice_xml(&xml)?;
let hash = invoice.hash_base64()?;
```

CLI
```bash
fatoora-rs-cli generate-hash --invoice invoice.xml
```
</details>

<details>
<summary>Invoice Request Payload</summary>

Rust
```rust
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

let xml = std::fs::read_to_string("signed.xml")?;
let signed = parse_signed_invoice_xml(&xml)?;
let payload = serde_json::json!({
    "invoiceHash": signed.invoice_hash(),
    "uuid": signed.uuid(),
    "invoice": signed.to_xml_base64(),
});
```

CLI
```bash
fatoora-rs-cli invoice-request --invoice signed.xml --api-request request.json
```
</details>

## Contributing

Contributions are always welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## Roadmap
- Increase test coverage to 100% (Inshallah)
- Add the full validation suite (not only UBL schema)
- Expand bindings to other languages (subject to demand)
- PDF invoice generation

## Relevant Links
- https://zatca.gov.sa/en/E-Invoicing/Pages/default.aspx
- https://sandbox.zatca.gov.sa/downloadSDK
- https://sandbox.zatca.gov.sa/IntegrationSandbox
