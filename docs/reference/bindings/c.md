# C and C++ bindings

The `fatoora-ffi` crate provides Diplomat-generated bindings. C headers are in
[bindings/c](../../../bindings/c), and C++ headers are in
[bindings/cpp](../../../bindings/cpp). Include the header for each type you use
and link `fatoora_ffi`. C++ classes live in namespace `fatoora`.

The generated ABI replaces the former handwritten ABI. Its symbols follow
`fatoora_Type_method`, such as `fatoora_Config_new`. Distribute matching headers
and libraries, and recompile callers when migrating. The old `fatoora_ffi.h`,
`fatoora.h`, `FfiResult`, and `*_free` interfaces are removed.

## C results and ownership

A fallible function returns a generated result type. For example, `Config.h`
defines:

```c
typedef struct fatoora_Config_new_result {
    union { Config *ok; BindingError *err; };
    bool is_ok;
} fatoora_Config_new_result;
```

Inspect `is_ok` before reading the union. A successful object pointer owns its
value; a failed result owns its `BindingError`. Destroy each owned pointer exactly
once with the corresponding function, such as `fatoora_Config_destroy` or
`fatoora_BindingError_destroy`. Void-success results contain only an error member;
scalar-success results contain the scalar in `ok`.

Opaque objects have no caller-visible fields. Optional results use the specific
representation in their generated header; an optional object can be a null
success pointer. Absence and an empty string are distinct.

Text inputs use `DiplomatStringView`, a pointer and byte length. The pointer must
identify valid readable storage for the call. The bridge validates UTF-8 and
rejects embedded NUL with an InvalidInput result. Numeric enum-like inputs are
validated too. Decimal quantities and amounts cross as exact decimal strings.

## Text and byte output

Text accessors write into a `DiplomatWrite`. Use `diplomat_simple_write` with a
caller-owned buffer, or allocate a growable writer with
`diplomat_buffer_write_create`. Read its byte pointer and length before destroying
it with `diplomat_buffer_write_destroy`. Copy the bytes if they must outlive the
writer. Check `grow_failed` when using an accessor whose signature returns void.

`Bytes` owns a byte buffer. `fatoora_Bytes_as_slice` returns a read-only
`DiplomatU8View` borrowed from that owner; copy the data before destroying the
`Bytes`. `BytesList::get` returns an independent owned `Bytes` object. Invoice,
party, address, and response getters also return owned snapshots that survive
destruction of their source object.

## C example

This example validates XML and prints a structured binding error's code and
message on failure. The deliberately incomplete invoice should fail validation.

```c
#include "BindingError.h"
#include "Config.h"
#include "Xml.h"
#include <stdio.h>
#include <string.h>

static void report_error(BindingError *error) {
    DiplomatWrite *message = diplomat_buffer_write_create(0);
    fatoora_BindingError_message(error, message);
    fprintf(stderr, "error %d: ", (int)fatoora_BindingError_code(error));
    if (message->grow_failed) {
        fputs("message buffer exhausted", stderr);
    } else {
        fwrite(diplomat_buffer_write_get_bytes(message), 1,
               diplomat_buffer_write_len(message), stderr);
    }
    fputc('\n', stderr);
    diplomat_buffer_write_destroy(message);
    fatoora_BindingError_destroy(error);
}

int main(void) {
    fatoora_Config_new_result created = fatoora_Config_new(0);
    if (!created.is_ok) {
        report_error(created.err);
        return 1;
    }
    const char *xml = "<Invoice></Invoice>";
    DiplomatStringView input = {xml, strlen(xml)};
    fatoora_Xml_validate_result result = fatoora_Xml_validate(created.ok, input);
    fatoora_Config_destroy(created.ok);
    if (!result.is_ok) {
        report_error(result.err);
        return 1;
    }
    printf("valid: %s\n", result.ok ? "true" : "false");
    return result.ok ? 0 : 1;
}
```

## C++ ownership

Generated C++ headers provide their own C-linkage declarations. Include them
directly; no external `extern "C"` wrapper is needed. They return
`diplomat::result` and manage objects with `std::unique_ptr`. Inspect `is_ok()`,
then move the result's `.ok()` or `.err()` value to take ownership. Owners release
their native objects automatically.

```cpp
#include "fatoora/BindingError.hpp"
#include "fatoora/Config.hpp"
#include "fatoora/Xml.hpp"
#include <iostream>
#include <utility>

int main() {
    auto created = fatoora::Config::new_(0);
    if (!created.is_ok()) {
        auto error = std::move(created).err().value();
        std::cerr << error->code() << ": " << error->message() << '\n';
        return 1;
    }
    auto config = std::move(created).ok().value();
    auto result = fatoora::Xml::validate(*config, "<Invoice></Invoice>");
    if (!result.is_ok()) {
        auto error = std::move(result).err().value();
        std::cerr << error->code() << ": " << error->message() << '\n';
        return 1;
    }
    return std::move(result).ok().value() ? 0 : 1;
}
```

Fallible C++ text accessors return a result containing `std::string`; error text
accessors return `std::string` directly. Owned strings survive destruction of
their source objects. Byte spans still borrow from their `Bytes` owner.

## Consumption and safety

Builder input errors allow correction. `build()` consumes the builder's inner
state even when final validation fails. Signing consumes a finalized invoice,
and `SignedInvoice::into_xml` consumes a signed invoice. Subsequent operations
on a consumed owner return an error; the owner remains safe to destroy.

Callers must provide valid pointers, preserve borrowed storage lifetimes, and
synchronize mutable access, consumption, and destruction. Malformed bytes are
validated only after the caller has supplied a valid byte view. Invalid pointers,
double destruction, and concurrent conflicting access violate the native contract.

Fallible operations catch unwinding Rust panics and return Internal errors.
Abort-mode panics and allocation aborts cannot be recovered this way. A panic
can leave an operation consumed; discard the affected owner after an Internal
failure. See [errors](../errors.md) for numeric codes and structured details.

## Build and link

Standalone C++ clients require C++17. The Python extension uses C++20. For example,
on Linux:

```sh
cargo build -p fatoora-ffi --release --locked
cc -std=c11 validate.c -I bindings/c -L target/release -lfatoora_ffi -o validate
c++ -std=c++17 validate.cpp -I bindings/cpp -L target/release -lfatoora_ffi -o validate_cpp
```

Configure the runtime loader to find the matching shared library. macOS uses the
`.dylib`; Windows uses the DLL and its import library. Complete executable
contracts are in [diplomat_contract.c](../../../fatoora-ffi/tests/diplomat_contract.c)
and [diplomat_contract.cpp](../../../fatoora-ffi/tests/diplomat_contract.cpp).

See [generation and verification](../../development/diplomat.md) and
[Python bindings](python.md).
