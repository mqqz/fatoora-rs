# FFI Parity Workflow

The Rust core is the source of truth. All language bindings should match the Rust public API by implementing the same capabilities via the FFI layer. This page tracks what is covered, what is intentionally omitted, and what is missing.

## Workflow
1. Add or change the public API in `fatoora-core`.
2. Extend `fatoora-ffi` to expose the new capability.
3. Regenerate headers (`fatoora-ffi/include/fatoora_ffi.h`).
4. Update each language binding to wrap the new FFI symbols.
5. Add or update parity tests in each binding.
6. Ensure FFI enums keep explicit discriminants and string handling stays strict UTF-8.

## Parity Table (Current)
Status values:
- Done: exposed and in headers.
- Omitted (intentional): not exposed by design.
- Missing (yet to be added): public core API with no FFI equivalent.

| Core public API item | FFI symbol(s) | Status | Notes |
| --- | --- | --- | --- |
| `config::Config::new` + `EnvironmentType` | `fatoora_config_new`, `FfiEnvironment` | Done | `fatoora_config_new` returns a raw handle, not `FfiResult`. |
| `config::Config::env` | `fatoora_config_env` | Done |  |
| `csr::CsrProperties::parse_csr_config` | `fatoora_csr_properties_parse` | Done |  |
| `csr::CsrProperties::parse_csr_config_file` | `fatoora_csr_properties_parse_file` | Done |  |
| `csr::SigningKey::{generate,from_pem,from_der}` | `fatoora_signing_key_generate`, `fatoora_signing_key_from_pem`, `fatoora_signing_key_from_der` | Done |  |
| `csr::SigningKey::to_pem` | `fatoora_signing_key_to_pem` | Done |  |
| `csr::SigningKey::to_der` | `fatoora_signing_key_to_der` | Done | Uses `FfiBytes`. |
| `csr::CsrProperties::build` | `fatoora_csr_build` | Done |  |
| `csr::Csr::to_base64` | `fatoora_csr_to_base64` | Done |  |
| `csr::Csr::to_pem_base64` | `fatoora_csr_to_pem_base64` | Done |  |
| `csr::Csr::from_der` | `fatoora_csr_from_der` | Done |  |
| `csr::Csr::to_pem` | `fatoora_csr_to_pem` | Done |  |
| `csr::Csr::to_der` | `fatoora_csr_to_der` | Done | Uses `FfiBytes`. |
| `csr::Csr::subject_string` | `fatoora_csr_subject_string` | Done |  |
| `csr::Csr::extension_values_der` | `fatoora_csr_extension_values_der` | Done | Uses `FfiBytesList`. |
| `invoice::InvoiceBuilder` + setters | `fatoora_invoice_builder_*` | Done |  |
| `invoice::FinalizedInvoice` data accessors | `fatoora_invoice_*` | Done | Includes line items, totals, parties, flags, type/subtype. |
| `invoice::SignedInvoice` data accessors | `fatoora_signed_invoice_*` | Done | Mirrors finalized for core data; signed-only accessors also present. |
| `invoice::SignedInvoice::zatca_key_signature` | `fatoora_signed_invoice_zatca_key_signature` | Done |  |
| `invoice::sign::InvoiceSigner::{from_pem,from_der,sign}` | `fatoora_signer_from_pem`, `fatoora_signer_from_der`, `fatoora_invoice_sign` | Done |  |
| `invoice::sign::InvoiceSigner::sign_xml` | — | Missing (yet to be added) |  |
| `invoice::sign::invoice_hash_base64_from_xml_str` | — | Missing (yet to be added) |  |
| `invoice::xml::parse_*_xml` | `fatoora_parse_*_invoice_xml` | Done |  |
| `invoice::xml::parse_*_xml_file` | `fatoora_parse_*_invoice_xml_file` | Done |  |
| `invoice::validation::validate_xml_invoice_from_str` | `fatoora_validate_xml_str` | Done | FFI returns `bool` only. |
| `api::ZatcaClient` (check/report/clear/renew) | `fatoora_zatca_*` | Done |  |
| `api::CsidCredentials` | `fatoora_csid_*` | Done | `request_id` is a UTF-8 string; empty string is the sentinel. |
| `api::CsidCredentials::env` | `fatoora_csid_*_env` | Done |  |
| `invoice::CountryCode/CurrencyCode/InvoiceTimestamp` types | — | Omitted (intentional) | FFI takes validated strings at the boundary. |

## Conformance Tests
Define a minimal cross-language scenario and keep it consistent across bindings:
- CSR generation
- Invoice build
- Signing
- Validation
- QR extraction

Each binding should run the same scenario and assert on key outputs (XML well-formed, hash present, QR payload length, etc.).

## Intentionally Omitted from FFI
- Error enums and structured error responses (handled via `FfiErrorKind` + message).
- Internal builder/view types (`InvoiceView`).
- XML formatting types (`ToXml`, internal parse helpers).
- QR structured types (`QrPayload`, `QrResult`) when a QR string is sufficient.
