---
title: C and C++ ZATCA e-invoicing bindings
description: Compile and link fatoority, handle return values and errors, and manage text, byte and invoice ownership in C or C++.
---

# C and C++ bindings

Use the native library to create CSRs, build and sign invoices, validate XML and call the ZATCA API. Headers and the shared library must come from the same release. Download them from the [release assets](https://github.com/mqqz/fatoority/releases).

Configure your runtime loader to find the shared library: `.so` on Linux, `.dylib` on macOS, or the DLL on Windows. Select your language for its include paths, return values and cleanup rules.

=== "C"

    Include one header, check the shared status, and release returned owners. Passing
    `NULL` as the error argument is supported when only the status matters. The
    deliberately incomplete invoice below fails validation.

    ```c
    #include "fatoora.h"
    #include <stdio.h>

    int main(void) {
        FatooraConfig *config = NULL;
        FatooraError *error = NULL;
        bool valid = false;
        FatooraStatus status = fatoora_config_new(FATOORA_NON_PRODUCTION, &config, &error);
        if (status == FATOORA_OK)
            status = fatoora_xml_validate(config, "<Invoice></Invoice>", &valid, &error);
        if (status == FATOORA_OK) printf("valid: %s\n", valid ? "true" : "false");
        else fprintf(stderr, "error %d: %s\n", (int)status, fatoora_error_message(error));
        fatoora_error_free(error);
        fatoora_config_free(config);
        return status == FATOORA_OK && valid ? 0 : 1;
    }
    ```

    String getters return owned `char *` values through output pointers; release
    them with `fatoora_string_free()`. Optional text returns `NULL` for absence and
    an allocated empty string for a present empty value. Decimal values are exact
    strings. Constructors and line items use named-field option structs. See the
    [complete builder example](https://github.com/mqqz/fatoority/blob/main/bindings/c/examples/build_invoice.c)
    and the ownership rules below.


    **Compile and link**

    Use matching headers and native libraries from the same release. Compile `bindings/c/fatoora.c` once alongside your application, include `bindings/c`, and link `fatoora_ffi`:

    ```sh
    cc -std=c11 validate.c bindings/c/fatoora.c \
      -Ibindings/c -L/path/to/native-library -lfatoora_ffi -o validate
    ```

    Release archives use `include/fatoora.h`, `src/fatoora.c` and `include/generated/`. Compile the archive's `src/fatoora.c` with `-Iinclude` and link the matching native library. If your application is C++, compile this adapter as C, then link the object into your application.

    **Values and ownership**

    | Value | Contract |
    | --- | --- |
    | Text input | Borrowed NUL-terminated UTF-8 for the duration of the call |
    | Optional text input | `NULL` means absent; `""` is present empty text |
    | Decimal input | Exact decimal string; no exponent or whitespace |
    | Text output | Owned `char *`; free with `fatoora_string_free` |
    | Object output | Owned opaque handle; free with its `fatoora_<type>_free` function |
    | Byte output | `FatooraBytes` owner; its data view borrows from that owner |
    | Error | Owned `FatooraError`; its message and details strings borrow from the error |
    | Output arguments | Cleared on entry; free any old value before reusing its slot |

    Invoice, party, address and response getters return independent owned snapshots. They survive destruction of the source object. Optional owned output is `NULL` when absent. Freeing a null owner is safe. Passing `NULL` for the error-output slot discards detailed diagnostics but retains the returned status.

    Do not copy opaque owners by value or free them with the system allocator. `FATOORA_OK` from local invoice validation means a report was produced; inspect `is_valid` in that report.

=== "C++"

    C++ headers provide their own C-linkage declarations. Include them
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


    **Compile and link**

    Use C++17 or later and headers matching the native library release:

    ```sh
    c++ -std=c++17 validate.cpp -Ibindings/cpp \
      -L/path/to/native-library -lfatoora_ffi -o validate_cpp
    ```

    Text inputs are borrowed for the call. Decimal inputs and outputs use exact strings. Optional text can be an absent owner; inspect the result before dereferencing it. Returned invoice, party, address and response objects are independent snapshots. Keep a `Bytes` owner alive while using its byte span.

## Consumption and safety

Builder input errors allow correction. `build()` consumes the builder's inner
state even when final validation fails. Signing consumes a finalized invoice,
and the consuming XML getter consumes a signed invoice. Subsequent operations
on a consumed owner return an error; the owner remains safe to destroy.

Callers must provide valid pointers, preserve borrowed storage lifetimes, and
synchronize mutable access, consumption, and destruction. Malformed bytes are
validated only after the caller has supplied a valid byte view. Invalid pointers,
double destruction, and concurrent conflicting access violate the native contract.

Fallible operations catch unwinding Rust panics and return Internal errors.
Abort-mode panics and allocation aborts cannot be recovered this way. A panic
can leave an operation consumed; discard the affected owner after an Internal
failure. See [errors](../errors.md) for numeric codes and structured details.


## Reference by operation

- [Configuration](../configuration.md): environment selection.
- [CSR and keys](../csr.md): certificate requests and key export.
- [Invoice model](../invoice-model.md): builder fields, amounts and returned snapshots.
- [Signing](../invoice-signing.md) and [XML](../xml.md): signing, parsing and hashes.
- [Validation](../invoice-validation.md): schema results and local reports.
- [API client](../api-client.md): credentials, submissions and response acceptance.
- [Errors](../errors.md): numeric status categories and JSON diagnostics.
