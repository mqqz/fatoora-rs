# FFI Parity Workflow

The Rust core is the source of truth. All language bindings should match the Rust public API by implementing the same capabilities via the FFI layer.

## Workflow
1. Add or change the public API in `fatoora-core`.
2. Extend `fatoora-ffi` to expose the new capability.
3. Regenerate headers (`fatoora-ffi/include/fatoora_ffi.h`).
4. Update each language binding to wrap the new FFI symbols.
5. Add or update parity tests in each binding.

## Parity Checklist (Template)
Use this table to track coverage for each new Rust API item.

| Rust API item | FFI symbol(s) | Python | C/C++ | Other bindings | Notes |
| --- | --- | --- | --- | --- | --- |
| `invoice::sign::InvoiceSigner::sign_xml` | `fatoora_invoice_sign` | TODO | TODO | TODO |  |
| `invoice::validation::validate_xml_invoice_from_str` | `fatoora_validate_xml_str` | DONE | TODO | TODO |  |

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
- Internal builder/view types (`InvoiceView`, `RequiredInvoiceFields`, `LineItem*Fields`).
- XML model/formatting types (`InvoiceXml`, `XmlFormat`, `ToXml`, `ParseError`).
- QR structured types (`QrPayload`, `QrResult`) when a QR string is sufficient.
