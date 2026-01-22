# Core

The `fatoora-core` crate is the primary Rust API. It provides configuration, CSR generation,
invoice models/builders, XML/signing/validation helpers, QR payload support, and the ZATCA API
client.

## Modules
- `config`: environment selection and schema paths.
- `csr`: CSR properties parsing and CSR/key generation helpers.
- `invoice`: invoice model, builders, XML serialization/parsing, validation, signing, and QR.
- `api`: ZATCA HTTP client and response types.

## Errors
- `Error` is the top-level error wrapper for core operations. It converts from invoice, signing,
  QR, XML serialization/parsing, XML validation, CSR, and API client errors, so you can use `?`
  across module boundaries without custom mapping.
