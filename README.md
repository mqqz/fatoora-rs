<h1 align="center">  
  🇸🇦 fatoora-rs 🧾 
  </br>
  <a href="https://github.com/mqqz/fatoora-rs">
    <img src="https://github.com/mqqz/fatoora-rs/blob/main/docs/assets/images/crab-logo.webp" height=150px alt="fatoora-rs-logo">
  </a>
</h1>
<p align="center">
<a target="_blank" href="https://choosealicense.com/licenses/mit"><img src="https://img.shields.io/badge/License-MIT-green.svg"/></a> 
<a href="https://codecov.io/gh/mqqz/fatoora-rs"><img src="https://codecov.io/gh/mqqz/fatoora-rs/graph/badge.svg?token=JRI6609XU6"/></a>
</p>
<p align="center">
<a href="https://rs.fatoority.com">🌐 Homepage</a> &nbsp;&bull;&nbsp;
<a href="#-features">⚡ Features</a> &nbsp;&bull;&nbsp;
<a href="#-installation">📥 Installation</a> &nbsp;&bull;&nbsp;
<a href="#-examples">💡 Examples</a> &nbsp;&bull;&nbsp;
<a href="#%EF%B8%8F-documentation">🗂️ Documentation</a>
</p>

#

An *unofficial* open-source toolkit for everything you'd need for ZATCA (Zakat, Tax and Customs Authority of Saudi Arabia) Phase 1 and 2 compliant e-invoicing.

With bindings and support for many programming languages:
- 🦀 Rust <a href="https://crates.io/crates/fatoora-core"><img src="https://img.shields.io/crates/v/fatoora-core?logo=rust&label=fatoora-core" alt="fatoora-core Crates.io Version"/></a>
  
- 🐍 Python <a href="https://pypi.org/project/fatoora-rs/"><img src="https://img.shields.io/pypi/v/fatoora-rs?logo=python" alt="PyPi Version"/></a>

- 🌀 C/C++ (through the C FFI see ![releases](https://github.com/mqqz/fatoora-rs/releases))

- 🔌 Also, a Command Line Interface (CLI) Tool  <a href="https://crates.io/crates/fatoora-rs-cli"><img src="https://img.shields.io/crates/v/fatoora-rs-cli?logo=rust&label=fatoora-rs-cli" alt="fatoora-rs-cli Crates.io Version"/></a>

> `fatoora-rs` is in active early development. While the core functionality is usable, the public API is still evolving and may change as the project matures.
> We strive to maintain good test coverage and stability, but users should be aware that some rough edges may remain. 
> Feedback and contributions are especially welcome at this stage. 

**Disclaimer**:
`fatoora-rs` is not affiliated, associated, authorized, endorsed by, or in any way officially connected with ZATCA (Zakat, Tax and Customs Authority), or any of its subsidiaries or its affiliates. The official ZATCA website can be found at https://zatca.gov.sa.

## 🗂️ Documentation
Checkout the [homepage](https://rs.fatoority.com), also the Rust API at [docs.rs](https://docs.rs/fatoora-core/latest/fatoora_core/) may prove useful.

## ⚡ Features

Everything done by the official [ZATCA SDK](https://sandbox.zatca.gov.sa/downloadSDK) 
- 📩 [CSR Generation](https://rs.fatoority.com/guides/csr/)
- ✍️ [Invoice Signing](https://rs.fatoority.com/guides/invoice-signing/) (All invoice types)
- ✅ [Validation](https://rs.fatoority.com/guides/validation/) (UBL only for now)
- 🧾 [QR Generation](https://rs.fatoority.com/guides/qr/)
- 📨 [API Requests](https://rs.fatoority.com/guides/api/)

🚀 *But we do it faster and better* e.g. ~190x faster invoice hashing than ZATCA's SDK (see [`bench/`](https://github.com/mqqz/fatoora-rs/blob/main/bench/cli/results/hash_bench.md))

## 🧩 Dependencies
XML parsing/manipulation is done internally with `libxml2`, so you might need to install it if you haven't already. See [here](https://github.com/KWARC/rust-libxml?tab=readme-ov-file#installation-prerequisites) for relevant instructions.

## 📥 Installation
<details>
<summary>Rust</summary>
  
```
cargo add fatoora-core
```
</details>

<details>
<summary>Python</summary>
  
```
pip install fatoora-rs
```
</details>

<details>
<summary>C/C++</summary>
  
Download the precompiled shared library and headers for your platform on the repo's [releases](https://github.com/mqqz/fatoora-rs/releases) (`fatoora-ffi-*`).

Alternatively, if you'd like to build from source. Clone the repo and run:
```
cargo build -p fatoora-ffi --release
```

The compiled library will be in `target/release/` for your platform (e.g. `libfatoora_ffi.so`, `libfatoora_ffi.dylib`, or `fatoora_ffi.dll`) and the headers will be (re)generated and written to `fatoora-ffi/include/`
</details>

<details>
<summary>CLI</summary>
  
The cli tool can also be installed with `cargo`: 

```
cargo install fatoora-rs-cli
```
Alternatively, you can grab the precompiled binary for your platform on the repo's [releases](https://github.com/mqqz/fatoora-rs/releases) (`fatoora-rs-cli-*`).
</details>

## 💡 Examples

<details>
<summary>CSR Generation</summary>

Rust
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

Python
```python
from fatoora.config import Environment
from fatoora.csr import CsrProperties, SigningKey

props = CsrProperties.parse_csr_config_file("csr.properties")
key = SigningKey.generate()
csr = props.build(key, Environment.NON_PRODUCTION)
csr_pem = csr.to_pem_base64()
key_pem = key.to_pem()
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

And much more... see the guides in the [homepage](https://rs.fatoority.com/) for more info.

## 🤝 Contributing

Contributions are always welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## 🪧 Roadmap
- Increase test coverage to 100% (Inshallah)
- Add the full validation suite (not only UBL schema)
- Expand bindings to other languages (subject to demand)
- PDF invoice generation

## 🔗 Relevant Links
- [ZATCA E-Invoicing Homepage](https://zatca.gov.sa/en/E-Invoicing/Pages/default.aspx)
- [ZATCA Fatoora SDK](https://sandbox.zatca.gov.sa/downloadSDK)
- [ZATCA API Sandbox](https://sandbox.zatca.gov.sa/IntegrationSandbox)
