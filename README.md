
# `fatoora-rs`
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)

An *unofficial* open-source toolkit for everything you'd need for ZATCA (Zakat, Tax and Customs Authority of Saudi Arabia) Phase 1 and 2 compliant e-invoicing 

...with bindings and support for many programming languages (coming soon lol).

...*and also built in Rust btw*

> `fatoora-rs` is in active early development. While the core functionality is usable, the public API is still evolving and may change as the project matures.
> We strive to maintain good test coverage and stability, but users should be aware that some rough edges may remain. 
> Feedback and contributions are especially welcome at this stage. 

**Disclaimer**:
`fatoora-rs` is not affiliated, associated, authorized, endorsed by, or in any way officially connected with ZATCA (Zakat, Tax and Customs Authority), or any of its subsidiaries or its affiliates. The official ZATCA website can be found at https://zatca.gov.sa.

## Documentation
WIP

## Features

Everything done by the official [ZATCA SDK](https://sandbox.zatca.gov.sa/downloadSDK) (but faster and better)
- CSR Generation
- Invoice Signing (All invoice types)
- Validation (UBL only for now)
- QR Generation
- API Requests

## Dependancies
XML parsing/manipulation is done internally with `libxml2`, so you might need to install it if you haven't already see [here](https://github.com/KWARC/rust-libxml?tab=readme-ov-file#installation-prerequisites) for relevant instructions.

## Usage/Examples

<details>
<summary>CSR Generation</summary>
```rust
CODE!
```
</details>

<details>
<summary>Invoice Signing</summary>
```rust
CODE!
```
</details>

## Contributing

Contributions are always welcome!
- Open issues for discussion before implementing any big features
- Add relevant tests and make sure there are no formatting issues.

## Roadmap
- Add the full validation suite (not only UBL schema)
- Expand bindings to other languages (subject to demand)
- PDF invoice generation

## Relevant Links
- https://zatca.gov.sa/en/E-Invoicing/Pages/default.aspx
- https://sandbox.zatca.gov.sa/downloadSDK
- https://sandbox.zatca.gov.sa/IntegrationSandbox
