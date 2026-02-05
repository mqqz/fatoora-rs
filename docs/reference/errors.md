# Errors

Error types used across the core library, FFI, and Python bindings.

## Rust

??? note "Error types"
    Core error types and categories.

    ```rust
    ErrorKind
    Error
    InvoiceError
    ValidationError
    CsrError
    SigningError
    XmlValidationError
    InvoiceXmlError
    ParseError
    ZatcaError
    ```

    !!! info "Returns"
        - Typed errors for each domain (invoice, CSR, signing, XML, API).

## Python

??? note "Exceptions"
    Python exception hierarchy.

    ```python
    FatooraError
    FfiError
    InvalidInputError
    ValidationError
    ParseError
    XmlError
    CryptoError
    IoError
    NetworkError
    UnauthorizedError
    InternalError
    ApiError
    ```

    !!! info "Returns"
        - Typed exceptions for FFI, parsing, crypto, IO, networking, and API failures.

## C (FFI)

??? note "FFI errors"
    FFI error type and helpers.

    ```c
    FfiErrorKind
    FfiError
    int fatoora_error_code(FfiError* error);
    FfiString fatoora_error_message(FfiError* error);
    void fatoora_error_free(FfiError* error);
    ```

    !!! info "Args"
        - `error`: error handle returned from a failed FFI call.

    !!! info "Returns"
        - `code`: numeric error kind.
        - `message`: UTF-8 error message.

## Mapping (FFI -> Python)

!!! note "Mapping"
    - InvalidInput -> InvalidInputError
    - Validation -> ValidationError
    - Parse -> ParseError
    - Xml -> XmlError
    - Crypto -> CryptoError
    - Io -> IoError
    - Network -> NetworkError
    - Unauthorized -> UnauthorizedError
    - Internal -> InternalError
    - Api -> ApiError

