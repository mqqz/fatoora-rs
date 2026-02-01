# Core

`fatoora-core` is the Rust source of truth. The FFI layer and Python bindings are thin wrappers over
this crate.

## Modules
- `config`: environment selection for API base URLs.
- `csr`: CSR properties parsing, key handling, and CSR build/serialization.
- `invoice`: invoice model/builder, XML, signing, validation, and QR helpers.
- `api`: ZATCA HTTP client and response types.

## Error model
- `ErrorKind` is the stable error code set used across Rust and FFI.
- `Error` is the unified core error type with `kind()` and `message()`.

## Symbols

=== "Rust"
    - Crate: `fatoora_core` — exposes `config`, `csr`, `invoice`, and `api` modules.
    - `ErrorKind` — enum of stable error categories.
    - `Error::new(kind: ErrorKind, message: impl Into<String>) -> Error` — construct a core error.
    - `Error::kind(&self) -> ErrorKind` — read the stable kind code.
    - `Error::message(&self) -> &str` — read the human message.

=== "Python"
    - Package: `fatoora` — re-exports public API (config, csr, invoice, api, errors).

=== "C (FFI)"
    - Header: `fatoora_ffi.h` — full C ABI surface.
    - Alias header: `fatoora.h` — optional alias without the `fatoora_` prefix.
