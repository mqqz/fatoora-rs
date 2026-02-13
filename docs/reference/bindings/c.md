# C/C++ Bindings

The C ABI is provided by the `fatoora-ffi` crate and can be used from C or C++.

## FFI Layer

???+ note "Headers"
    ```c
    fatoora_ffi.h
    fatoora.h
    ```

    !!! info "Returns"
        - `fatoora_ffi.h`: full ABI surface.
        - `fatoora.h`: alias header without the fatoora_ prefix (compile with -DFATOORA_FFI_NO_PREFIX).

???+ note "Ownership and results"
    - Opaque handles (Ffi*) are created and freed with explicit *_free functions.
    - All fallible calls return FfiResult<T>.
    - Strings and byte buffers returned from FFI must be freed by the caller.

???+ note "Result and buffers"
    ```c
    struct FfiResult<T> { bool ok; T value; FfiError* error; }
    struct FfiError { int32_t code; char* message; }
    struct FfiString { char* ptr; }
    struct FfiBytes { uint8_t* ptr; uintptr_t len; }
    struct FfiBytesList { FfiBytes* ptr; uintptr_t len; }
    ```

    !!! info "Returns"
        - `FfiResult<T>`: check ok before using value.
        - `FfiString` / `FfiBytes` / `FfiBytesList`: heap buffers that must be freed by the caller.

???+ note "Error helpers"
    ```c
    enum FfiErrorKind { ... };
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
    - Some getters return optional handles (NULL pointer on success when the field is absent).
    - Signed invoice getters return signature metadata (hash, signature, public key, signed props hash, signing time) as UTF-8 strings.

## Usage Notes
- Most handles are opaque pointers and must be freed with their corresponding `*_free` functions.
- Strings returned by the FFI should be freed with `fatoora_string_free`.
- Errors are returned as `FfiError` handles; use `fatoora_error_message` and `fatoora_error_code`, then free with `fatoora_error_free`.
- Invoice builder timestamps are strings in ZATCA ISO UTC format (`YYYY-MM-DDTHH:MM:SSZ`), and
  country/currency codes are validated strings.
- ZATCA API responses are opaque handles with getter functions (no JSON payloads).
- Signed invoice metadata can be read via `fatoora_signed_invoice_signature`, `fatoora_signed_invoice_public_key`,
  `fatoora_signed_invoice_cert_hash`, `fatoora_signed_invoice_signed_props_hash`, and `fatoora_signed_invoice_signing_time`.
  `fatoora_signed_invoice_signing_time` returns a `YYYY-MM-DDTHH:MM:SS` UTC string.

## Minimal C example (validation)
```c
#include <stdio.h>
#include "fatoora_ffi.h"

int main(void) {
    struct FfiConfig *config = fatoora_config_new(FfiEnvironment_NonProduction);
    const char *xml = "<Invoice></Invoice>";

    struct FfiResult_bool result = fatoora_validate_xml_invoice_from_str(config, xml);
    if (!result.ok) {
        fprintf(stderr, "validation error: %s\n", result.error);
        fatoora_error_free(result.error);
    } else {
        printf("valid: %s\n", result.value ? "true" : "false");
    }

    fatoora_config_free(config);
    return 0;
}
```

## C++ include pattern
The header does not wrap symbols in `extern "C"`. Do that in your C++ translation unit:
```cpp
extern "C" {
#include "fatoora_ffi.h"
}
```

## Linking
Example for Linux:
```bash
cc examples/validate.c -I fatoora-ffi/include -L target/release -lfatoora_ffi -o validate
```

On macOS use `-lfatoora_ffi` with the `.dylib` in `target/release/`.
On Windows link against `fatoora_ffi.dll` (and its import library if your toolchain requires it).

See also: [Python Bindings](python.md)
