
# `fatoora-rs`
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![codecov](https://codecov.io/gh/mqqz/fatoora-rs/graph/badge.svg?token=JRI6609XU6)](https://codecov.io/gh/mqqz/fatoora-rs) 
[![Crates.io Version](https://img.shields.io/crates/v/fatoora-core?logo=rust&label=fatoora-core)](https://crates.io/crates/fatoora-core)
[![Crates.io Version](https://img.shields.io/crates/v/fatoora-rs-cli?logo=rust&label=fatoora-rs-cli)](https://crates.io/crates/fatoora-rs-cli)
[![Crates.io Version](https://img.shields.io/crates/v/fatoora-derive?logo=rust&label=fatoora-derive)](https://crates.io/crates/fatoora-derive)


An *unofficial* open-source toolkit for everything you'd need for ZATCA (Zakat, Tax and Customs Authority of Saudi Arabia) Phase 1 and 2 compliant e-invoicing 

...with bindings and support for many programming languages (coming soon lol).

...*and also built in Rust btw*

> `fatoora-rs` is in active early development. While the core functionality is usable, the public API is still evolving and may change as the project matures.
> We strive to maintain good test coverage and stability, but users should be aware that some rough edges may remain. 
> Feedback and contributions are especially welcome at this stage. 

**Disclaimer**:
`fatoora-rs` is not affiliated, associated, authorized, endorsed by, or in any way officially connected with ZATCA (Zakat, Tax and Customs Authority), or any of its subsidiaries or its affiliates. The official ZATCA website can be found at https://zatca.gov.sa.

## Documentation
Check out [docs.rs](https://docs.rs/fatoora-core/latest/fatoora_core/) for the rust core library documentation.

## Features

Everything done by the official [ZATCA SDK](https://sandbox.zatca.gov.sa/downloadSDK) 
- CSR Generation
- Invoice Signing (All invoice types)
- Validation (UBL only for now)
- QR Generation
- API Requests

*But we do it faster and better* e.g. ~190x faster invoice hashing than ZATCA's SDK (see [`bench/`](https://github.com/mqqz/fatoora-rs/blob/main/bench/cli/results/hash_bench.md))

## Dependencies
XML parsing/manipulation is done internally with `libxml2`, so you might need to install it if you haven't already see [here](https://github.com/KWARC/rust-libxml?tab=readme-ov-file#installation-prerequisites) for relevant instructions.

## Installation
The rust library can be added with `cargo add fatoora-core`.

The cli tool can also be installed with `cargo`: 
```
cargo install fatoora-rs-cli
```

## Usage/Examples

<details>
<summary>CSR Generation</summary>

Rust
```rust
use fatoora_core::config::EnvironmentType;
use fatoora_core::csr::CsrProperties;

let props = CsrProperties::parse_csr_config("csr.properties".as_ref())?;
let (csr, key) = props.build_with_rng(EnvironmentType::NonProduction)?;
let csr_pem = csr.to_pem(Default::default())?;
let key_pem = key.to_pkcs8_pem(Default::default())?;
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
use fatoora_core::invoice::validation::validate_xml_invoice_from_file;

let config = Config::new(fatoora_core::config::EnvironmentType::NonProduction);
validate_xml_invoice_from_file("invoice.xml".as_ref(), &config)?;
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
use fatoora_core::invoice::sign::invoice_hash_base64;
use libxml::parser::Parser;

let xml = std::fs::read_to_string("invoice.xml")?;
let doc = Parser::default().parse_string(&xml)?;
let hash = invoice_hash_base64(&doc)?;
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

Contributions are always welcome!
- Open issues for discussion before implementing any big features
- Add relevant tests and make sure there are no formatting issues

> Live API tests run by default with the rest of the test suite.
> Set `SKIP_ZATCA_LIVE_API=1` to disable them locally or in CI.

## Roadmap
- Increase test coverage to 100% (Inshallah)
- Add the full validation suite (not only UBL schema)
- Expand bindings to other languages (subject to demand)
- PDF invoice generation

## Relevant Links
- https://zatca.gov.sa/en/E-Invoicing/Pages/default.aspx
- https://sandbox.zatca.gov.sa/downloadSDK
- https://sandbox.zatca.gov.sa/IntegrationSandbox
