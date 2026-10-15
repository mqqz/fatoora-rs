<h1 align="center">
  🇸🇦 fatoority 🧾
  </br>
  <a href="https://github.com/mqqz/fatoority">
    <img src="https://github.com/mqqz/fatoority/blob/main/docs/assets/images/crab-logo.webp" height=150px alt="fatoority-logo">
  </a>
</h1>
<p align="center">
<a target="_blank" href="#license"><img src="https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-green.svg"/></a>
<a href="https://codecov.io/gh/mqqz/fatoority"><img src="https://codecov.io/gh/mqqz/fatoority/graph/badge.svg?token=JRI6609XU6"/></a>
</p>
<p align="center">
<a href="https://docs.fatoority.com">🌐 Homepage</a> &nbsp;&bull;&nbsp;
<a href="#-features">⚡ Features</a> &nbsp;&bull;&nbsp;
<a href="#-installation">📥 Installation</a> &nbsp;&bull;&nbsp;
<a href="#-examples">💡 Examples</a> &nbsp;&bull;&nbsp;
<a href="#%EF%B8%8F-documentation">🗂️ Documentation</a>
</p>

#

An *unofficial* open-source toolkit for everything you'd need for ZATCA (Zakat, Tax and Customs Authority of Saudi Arabia) Phase 1 and 2 compliant e-invoicing.

With bindings and support for many programming languages:
- 🦀 Rust <a href="https://crates.io/crates/fatoora-core"><img src="https://img.shields.io/crates/v/fatoora-core?logo=rust&label=fatoora-core" alt="fatoora-core Crates.io Version"/></a>
  
- 🐍 Python <a href="https://pypi.org/project/fatoority/"><img src="https://img.shields.io/pypi/v/fatoority?logo=python" alt="PyPi Version"/></a>

- 🇯‌🇸‌ JavaScript / TypeScript <a href="https://www.npmjs.com/package/fatoority"><img src="https://img.shields.io/npm/v/fatoority?logo=javascript" alt="NPM Version"/></a>

- 🟣 C# / .NET <a href="https://www.nuget.org/packages/Fatoority"><img src="https://img.shields.io/nuget/v/Fatoority?logo=dotnet" alt="NuGet Version"/></a>

- ☕ [Kotlin / Java / Android](https://docs.fatoority.com/reference/bindings/kotlin/) <a href="https://central.sonatype.com/artifact/com.fatoority/fatoority"><img src="https://img.shields.io/maven-central/v/com.fatoority/fatoority?logo=kotlin" alt="Maven Central Version"/></a>

- 🌀 C/C++ (through the C FFI see ![releases](https://github.com/mqqz/fatoority/releases))

- 🔌 Also, a Command Line Interface (CLI) Tool  <a href="https://crates.io/crates/fatoora-cli"><img src="https://img.shields.io/crates/v/fatoora-cli?logo=rust&label=fatoora-cli" alt="fatoora-cli Crates.io Version"/></a>

**Disclaimer**:
`fatoority` is not affiliated, associated, authorized, endorsed by, or in any way officially connected with ZATCA (Zakat, Tax and Customs Authority), or any of its subsidiaries or its affiliates. The official ZATCA website can be found at https://zatca.gov.sa.

## 🗂️ Documentation
Checkout the [homepage](https://docs.fatoority.com), also the Rust API at [docs.rs](https://docs.rs/fatoora-core/latest/fatoora_core/) may prove useful.

## ⚡ Features

Everything done by the official [ZATCA SDK](https://sandbox.zatca.gov.sa/downloadSDK) 
- 📩 [CSR Generation](https://docs.fatoority.com/guides/csr/)
- ✍️ [Invoice Signing](https://docs.fatoority.com/guides/invoice-signing/) (All invoice types)
- ✅ [Validation](https://docs.fatoority.com/guides/validation/) (UBL and local ZATCA rules)
- 🧾 [QR Generation](https://docs.fatoority.com/guides/qr/)
- 📨 [API Requests](https://docs.fatoority.com/guides/api/)

🚀 *But we do it faster and better* e.g. ~190x faster invoice hashing than ZATCA's SDK (see [`bench/`](https://github.com/mqqz/fatoority/blob/main/bench/cli/results/hash_bench.md))
⚙️ Rigorously tested with fuzzing and ~97% coverage

## 📥 Installation
<details>
<summary>Rust</summary>
  
```sh
cargo add fatoora-core
```
</details>

<details>
<summary>Python</summary>
  
```sh
pip install fatoority
```
</details>

<details>
<summary>JavaScript</summary>

```sh
npm i fatoority
```
</details>

<details>
<summary>C# / .NET 8</summary>

```sh
dotnet add package Fatoority
```

The package uses namespace `Fatoora` and includes native libraries for Linux x64,
Windows x64, and macOS arm64.
See the [C# reference](https://docs.fatoority.com/reference/bindings/csharp/) for installation, deterministic
disposal, prepared HTTP requests, and package verification.

</details>

<details>
<summary>Kotlin / Java / Android</summary>

Install a published release from Maven Central.

**Gradle** (`build.gradle.kts`):

```kotlin
repositories { mavenCentral() }
dependencies {
    implementation("com.fatoority:fatoority:0.4.2")
}
```

**Maven** (`pom.xml`):

```xml
<dependency>
  <groupId>com.fatoority</groupId>
  <artifactId>fatoority</artifactId>
  <version>0.4.2</version>
</dependency>
```

For Android, use `com.fatoority:fatoority-android:0.4.2` instead of the desktop
artifact. Java/Kotlin imports remain `com.fatoora`.

The desktop package runs on Java 8+ and bundles Linux x86-64, Windows x86-64 and
macOS arm64 native libraries. Android supports API 26+ on `arm64-v8a` / `x86_64`.
See the [Kotlin / Java reference](https://docs.fatoority.com/reference/bindings/kotlin/)
for Android installation, platform prerequisites, ownership and coroutines.
For unpublished versions, use the
[local build instructions](bindings/kotlin/README.md#build-and-test).

</details>

<details>
<summary>C/C++</summary>
  
Download the `fatoora-ffi-*` archive for your platform from
[releases](https://github.com/mqqz/fatoority/releases) and extract it. The shared
library is at the archive root. The C API header is `include/fatoora.h`,
with its adapter in `src/fatoora.c` and generated headers in `include/generated`; C++ headers
are in `include/diplomat-cpp` and expose types in namespace `fatoora`.

For example, on Linux, compile your application from the extracted directory:

```sh
cc -std=c11 -Iinclude app.c src/fatoora.c -L. -lfatoora_ffi -Wl,-rpath,'$ORIGIN' -o app
c++ -std=c++17 -Iinclude/diplomat-cpp app.cpp -L. -lfatoora_ffi -Wl,-rpath,'$ORIGIN' -o app-cpp
```

Include `fatoora.h` in C or `fatoora/Config.hpp` in C++. Keep the shared library
beside these executables. On Windows, link the supplied import library and keep
the DLLs from the archive beside your executable.

To build the library from a source checkout:

```sh
cargo build -p fatoora-ffi --release --locked
```

The [C API](https://github.com/mqqz/fatoority/blob/main/docs/development/c-api.md)
provides one `fatoora.h`, plain strings, shared errors, and named-field options.
Compile `bindings/c/fatoora.c` once with your application, add `bindings/c` to
your include path, and link `fatoora_ffi`. Release archives also include the C
examples under `examples/c`.

The library is written to `target/release/`. The generated headers are checked in
under `bindings/c/generated` and `bindings/cpp`; raw ABI callers use those include paths and
`-Ltarget/release` when compiling against a source build. Cargo does not regenerate
headers. After changing bridge declarations, follow the
[Diplomat generation workflow](https://github.com/mqqz/fatoority/blob/main/docs/development/diplomat.md#generate-and-verify).
</details>

<details>
<summary>CLI</summary>
  
The cli tool can also be installed with `cargo`: 

```
cargo install fatoora-cli
```
Alternatively, you can grab the precompiled binary for your platform on the repo's [releases](https://github.com/mqqz/fatoority/releases) (`fatoora-cli-*`). Extract the archive and run `fatoora`.
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

JavaScript
```js
import { CsrProperties, SigningKey } from 'fatoority';

const key = SigningKey.generate();
const csr = CsrProperties.fromPropertiesStr(propertiesText).build(key, 0);
const csrPem = csr.toPem();
```

CLI
```bash
fatoora csr --csr-config csr.properties --generated-csr csr.pem --private-key key.pem --pem
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
fatoora sign --invoice invoice.xml --cert cert.pem --key key.pem --signed-invoice signed.xml
```
</details>

<details>
<summary>Validation</summary>

Rust
```rust
use fatoora_core::config::Config;
use fatoora_core::invoice::validation::{
    validate_zatca_invoice_from_str, ZatcaValidationOptions,
};

let config = Config::new(fatoora_core::config::EnvironmentType::NonProduction);
let xml = std::fs::read_to_string("invoice.xml")?;
let options = ZatcaValidationOptions {
    previous_invoice_hash: Some(previous_hash_from_history),
    ..Default::default()
};
let report = validate_zatca_invoice_from_str(&xml, &config, &options)?;
if !report.is_valid() {
    // Inspect stages and findings; missing predecessor context is incomplete.
}
```

CLI
```bash
fatoora validate --invoice invoice.xml --profile zatca --format json \
  --previous-invoice-hash "$PREVIOUS_INVOICE_HASH"
```

The local profile implements all 257 business-rule assertions from SDK
`238-R3.4.8`, plus applicable signature, QR and predecessor checks. It preserves
warnings and partial reports. Standard invoices skip signature/QR checks under
this SDK profile. Local validation does not establish issuer trust or remote
acceptance. Existing `validate_xml_invoice_from_str` and the default CLI profile
continue to check XSD only.
</details>

<details>
<summary>QR Generation & Reading</summary>

Rust
```rust
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;

let xml = std::fs::read_to_string("signed.xml")?;
let signed = parse_signed_invoice_xml(&xml)?;
let qr = signed.qr_code();
```

CLI
```bash
fatoora qr --invoice invoice.xml
fatoora qr --invoice signed.xml
fatoora qr --invoice signed.xml --fail-on-signed
fatoora qr-read --invoice signed.xml
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
fatoora generate-hash --invoice invoice.xml
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
fatoora invoice-request --invoice signed.xml --api-request request.json
```
</details>

And much more... see the guides in the [homepage](https://docs.fatoority.com/) for more info.

## 🤝 Contributing

Contributions are always welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## 🪧 Roadmap
- Increase test coverage to 100% (Inshallah)
- Expand bindings to other languages (subject to demand)
- PDF invoice generation

## Author 🤓

This project began as a personal undertaking, and 
continues to be developed and maintained by me [@mqqz](https://github.com/mqqz).

While this means development happens alongside other commitments, I do my
best to keep the project maintained and responsive to issues. Contributions,
feedback, and suggestions are always welcome.

If you or your team are working on fintech or ZATCA integrations and need help building
reliable scalable infrastructure, feel free to get in touch.

## 🔗 Relevant Links
- [ZATCA E-Invoicing Homepage](https://zatca.gov.sa/en/E-Invoicing/Pages/default.aspx)
- [ZATCA Fatoora SDK](https://sandbox.zatca.gov.sa/downloadSDK)
- [ZATCA API Sandbox](https://sandbox.zatca.gov.sa/IntegrationSandbox)

## License

This project's code is licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party schemas, fixtures, templates, and dependencies retain their applicable
upstream licenses and notices. The project license does not relicense those materials.

See [third-party notices](THIRD_PARTY_NOTICES.md) for attribution, applicable
terms, and outstanding permission questions.
