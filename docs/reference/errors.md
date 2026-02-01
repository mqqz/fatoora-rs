# Errors

Error types used across the core library, FFI, and Python bindings.

## Symbols

=== "Rust"
    - `ErrorKind` — stable error codes shared with FFI.
    - `Error` — unified core error with `kind()` and `message()`.
    - `InvoiceError` — invoice validation and ID format issues.
    - `ValidationError` — list of `ValidationIssue` entries.
    - `CsrError` — CSR parsing/build/encoding failures.
    - `SigningError` — signing, canonicalization, or key/cert failures.
    - `XmlValidationError` — schema and XML validation failures.
    - `InvoiceXmlError` — XML serialization errors.
    - `ParseError` — XML parsing and field extraction errors.
    - `ZatcaError` — API client errors.

=== "Python"
    - `FatooraError` — base exception.
    - `FfiError` — wraps FFI failures and includes `code`/`kind`.
    - `InvalidInputError`
    - `ValidationError`
    - `ParseError`
    - `XmlError`
    - `CryptoError`
    - `IoError`
    - `NetworkError`
    - `UnauthorizedError`
    - `InternalError`
    - `ApiError`

=== "C (FFI)"
    - `FfiErrorKind` — numeric codes matching `ErrorKind`.
    - `FfiError` — `{ code, message }` error handle.
    - `fatoora_error_code(error: FfiError*) -> int`
    - `fatoora_error_message(error: FfiError*) -> FfiString`
    - `fatoora_error_free(error: FfiError*) -> void`

## Mapping (FFI -> Python)
- `InvalidInput` -> `InvalidInputError`
- `Validation` -> `ValidationError`
- `Parse` -> `ParseError`
- `Xml` -> `XmlError`
- `Crypto` -> `CryptoError`
- `Io` -> `IoError`
- `Network` -> `NetworkError`
- `Unauthorized` -> `UnauthorizedError`
- `Internal` -> `InternalError`
- `Api` -> `ApiError`

See also: [Core Reference](core.md)
