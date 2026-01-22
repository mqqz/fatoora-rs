# C/C++ Bindings

The C ABI is provided by the `fatoora-ffi` crate and can be used from C or C++.

## Usage Notes
- Most handles are opaque pointers and must be freed with their corresponding `*_free` functions.
- Strings returned by the FFI should be freed with `fatoora_string_free`.
- Errors are returned as `FfiError` handles; use `fatoora_error_message` and `fatoora_error_code`, then free with `fatoora_error_free`.
- ZATCA API responses are opaque handles with getter functions (no JSON payloads).
- Signed invoice metadata can be read via `fatoora_signed_invoice_signature`, `fatoora_signed_invoice_public_key`,
  `fatoora_signed_invoice_cert_hash`, `fatoora_signed_invoice_signed_props_hash`, and `fatoora_signed_invoice_signing_time`.
- Module headers are available under `fatoora/` (e.g., `fatoora/config.h`, `fatoora/invoice.h`, `fatoora/api.h`).

## Minimal C example (validation)
```c
#include <stdio.h>
#include "fatoora/validation.h"
#include "fatoora/config.h"

int main(void) {
    struct FfiConfig *config = fatoora_config_new(FfiEnvironment_NonProduction);
    const char *xml = "<Invoice></Invoice>";

    struct FfiResult_bool result = fatoora_validate_xml_str(config, xml);
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
The header does not wrap symbols in `extern \"C\"`. Do that in your C++ translation unit:
```cpp
extern \"C\" {
#include \"fatoora/ffi.h\"
}
```

## Linking
Example for Linux:
```bash
cc examples/validate.c -I fatoora-ffi/include -L target/release -lfatoora_ffi -o validate
```

On macOS use `-lfatoora_ffi` with the `.dylib` in `target/release/`.
On Windows link against `fatoora_ffi.dll` (and its import library if your toolchain requires it).

See also: [FFI Reference](../reference/ffi.md)
