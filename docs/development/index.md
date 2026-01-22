# Development

Notes for contributors and maintainers. End-user usage is documented in the Guides.

## Build the FFI shared library
```bash
cargo build -p fatoora-ffi --release
```

The compiled library will be in `target/release/` for your platform (e.g. `libfatoora_ffi.so`, `libfatoora_ffi.dylib`, or `fatoora_ffi.dll`).

## Regenerate C headers
```bash
FATOORA_CBINDGEN=1 cargo build -p fatoora-ffi --release
```

Headers are written to `fatoora-ffi/include/`. `fatoora_ffi.h` uses the `fatoora_` prefix; `fatoora.h` provides alias names without the prefix when compiled with `-DFATOORA_FFI_NO_PREFIX`. Module headers are also available under `fatoora/` (e.g., `fatoora/config.h`, `fatoora/invoice.h`).

## FFI workflow
Use this flow for any new public capability:
1. Add or change the Rust API in `fatoora-core`.
2. Expose it in `fatoora-ffi` (prefer the macros in `fatoora-ffi/src/macros.rs`).
3. Regenerate headers (see above).
4. Update language bindings (Python, C/C++) to wrap the new symbols.
5. Add or update binding tests.

FFI conventions:
- Use opaque handles and `*_free` functions for ownership.
- Return `FfiResult<T>` everywhere and map errors via `FfiErrorKind`.
- Avoid filesystem access in the FFI; accept strings/bytes from callers.

## API audit
See `docs/development/api-audit.md` for the current core/FFI surface, proposed shape, and issues to address.

## Python bindings (uv)
```bash
uv venv
uv pip install -e bindings/python
```

## Build a Python wheel (uv)
```bash
uv build --wheel
```

## Tests
```bash
uv pip install -e bindings/python[dev]
uv run -c "import fatoora"
```
