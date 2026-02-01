# FFI Layer

C ABI bindings for the core library. The Python package is built on top of this FFI.

## Headers
- Main header: `fatoora_ffi.h`.
- Alias header without prefix: `fatoora.h` (compile with `-DFATOORA_FFI_NO_PREFIX`).
- Module headers live under `fatoora/` (e.g. `fatoora/config.h`, `fatoora/invoice.h`).

## Conventions
- Opaque handles (`Ffi*`) are created and freed with explicit `*_free` functions.
- All fallible calls return `FfiResult<T>`.
- Strings and byte buffers returned from FFI must be freed by the caller.

## Base types
- `struct FfiResult<T> { bool ok; T value; FfiError* error; }` — check `ok` before using `value`.
- `struct FfiError { int32_t code; char* message; }` — use `fatoora_error_*` accessors.
- `struct FfiString { char* ptr; }` — free with `fatoora_string_free`.
- `struct FfiBytes { uint8_t* ptr; size_t len; }` — free with `fatoora_bytes_free`.
- `struct FfiBytesList { FfiBytes* ptr; size_t len; }` — free with `fatoora_bytes_list_free`.

## Error helpers
- `fatoora_error_code(error: FfiError*) -> int` — numeric `ErrorKind`.
- `fatoora_error_message(error: FfiError*) -> FfiString` — UTF-8 message string.
- `fatoora_error_free(error: FfiError*) -> void` — free the error handle.

## Notes
- FFI error codes map directly to Rust `ErrorKind` and Python `FfiErrorKind`.
- Signed invoice getters return signature metadata (hash, signature, public key, signed props hash,
  signing time) as UTF-8 strings.

For contributor workflows (adding new FFI endpoints, macro usage, header regeneration), see
[FFI Workflow](../development/ffi-workflow.md).

See also: [Python Bindings Guide](../guides/python-bindings.md) and [C/C++ Bindings Guide](../guides/c-bindings.md)
