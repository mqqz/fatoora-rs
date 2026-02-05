# FFI Layer

C ABI bindings for the core library. The Python package is built on top of this FFI.

## Headers

??? note "Headers"
    ```c
    fatoora_ffi.h
    fatoora.h
    ```

    !!! info "Returns"
        - `fatoora_ffi.h`: full ABI surface.
        - `fatoora.h`: alias header without the fatoora_ prefix (compile with -DFATOORA_FFI_NO_PREFIX).

## Conventions

??? note "Ownership and results"
    - Opaque handles (Ffi*) are created and freed with explicit *_free functions.
    - All fallible calls return FfiResult<T>.
    - Strings and byte buffers returned from FFI must be freed by the caller.

## Base Types

??? note "Result and buffers"
    ```c
    struct FfiResult<T> { bool ok; T value; FfiError* error; }
    struct FfiError { int32_t code; char* message; }
    struct FfiString { char* ptr; }
    struct FfiBytes { uint8_t* ptr; size_t len; }
    struct FfiBytesList { FfiBytes* ptr; size_t len; }
    ```

    !!! info "Returns"
        - `FfiResult<T>`: check ok before using value.
        - `FfiString` / `FfiBytes` / `FfiBytesList`: heap buffers that must be freed by the caller.

## Error Helpers

??? note "Read and free"
    ```c
    int fatoora_error_code(FfiError* error);
    FfiString fatoora_error_message(FfiError* error);
    void fatoora_error_free(FfiError* error);
    ```

    !!! info "Args"
        - `error`: error handle from a failed FFI call.

    !!! info "Returns"
        - `code`: numeric error kind.
        - `message`: UTF-8 error message.

!!! note "Notes"
    - FFI error codes map directly to Rust ErrorKind and Python FfiErrorKind.
    - Signed invoice getters return signature metadata (hash, signature, public key, signed props hash, signing time) as UTF-8 strings.

See also: [FFI Workflow](../development/ffi-workflow.md), [Python Bindings Guide](../guides/python-bindings.md), [C/C++ Bindings Guide](../guides/c-bindings.md)
