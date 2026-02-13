# Errors

Error types used across the core library, FFI, and Python bindings.

## ErrorKind / FfiErrorKind

### categories

???+ note "Error categories"
    Shared high-level categories for validation, parsing, XML, crypto, IO, network, unauthorized, internal, and API errors.

    === "{{ lang.rust }}"
        ```rust
        ErrorKind
        ```

    === "{{ lang.python }}"
        ```python
        FfiErrorKind
        ```

    === "{{ lang.c }}"
        ```c
        enum FfiErrorKind { ... };
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

## Domain Errors (Rust)

### error types

???+ note "Core error types"

    === "{{ lang.rust }}"
        ```rust
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
        - Types are language-specific and shown in the active tab signature above.

## Exceptions (Python)

### exception hierarchy

???+ note "Python exceptions"

    === "{{ lang.python }}"
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
        - Types are language-specific and shown in the active tab signature above.

## FfiError

### `fatoora_error_code`

???+ note "Read numeric error code"

    === "{{ lang.c }}"
        ```c
        int fatoora_error_code(FfiError* error);
        ```

    !!! info "Args / Returns"
        - Types are language-specific and shown in the active tab signature above.

### `fatoora_error_message`

???+ note "Read error message"

    === "{{ lang.c }}"
        ```c
        FfiString fatoora_error_message(FfiError* error);
        ```

    !!! info "Args / Returns"
        - Types are language-specific and shown in the active tab signature above.

### `fatoora_error_free`

???+ note "Free error handle"

    === "{{ lang.c }}"
        ```c
        void fatoora_error_free(FfiError* error);
        ```

    !!! info "Args / Returns"
        - Types are language-specific and shown in the active tab signature above.

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
