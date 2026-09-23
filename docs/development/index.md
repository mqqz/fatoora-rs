# Development

Notes for contributors and maintainers. End-user usage is documented in the Guides.

## Why
This project exists because the official SDK and documentation were not meeting day-to-day needs. Common tasks felt harder than they should be: the API surface was inconsistent, error handling was unclear, and examples rarely matched real workflows. Fatoora started as an effort to build a clean, predictable SDK with solid defaults, thorough tests, and bindings that behave the same across languages.

We prioritize:

- A small, well-typed core API with explicit errors.

- A stable FFI layer for bindings and long-term compatibility.

- Docs and examples that reflect the actual behavior, not just happy paths.

## Quick Start
There are two main ways to use `fatoora-rs`:

- **CLI**: Best for quick validation, local workflows, and CI scripts. 

    See the Guides for install and usage examples.

- **Library**: Use the Rust crate directly, or use language bindings that wrap the shared FFI. 
    
    This is typically the case for integrating into applications or services.

## Build the FFI shared library
```bash
cargo build -p fatoora-ffi --release
```

The compiled library will be in `target/release/` for your platform (e.g. `libfatoora_ffi.so`, `libfatoora_ffi.dylib`, or `fatoora_ffi.dll`).

## Regenerate C headers
```bash
cargo build -p fatoora-ffi --release
```

Diplomat generates checked-in C/C++ headers and Python native sources. Follow the [binding workflow](diplomat.md); do not edit generated files manually.

## FFI workflow

Use this flow for any new public capability:

1. Add or change the Rust API in `fatoora-core`.
2. Expose it in `fatoora-ffi` (prefer the macros in `fatoora-ffi/src/macros.rs`).
3. Regenerate headers (see above).
4. Update language bindings (Python, C/C++) to wrap the new symbols.
5. Add or update binding tests and docs.

FFI conventions:
- Use opaque handles and `*_free` functions for ownership.
- Return `FfiResult<T>` everywhere and map errors via `FfiErrorKind`.

## API audit
See `docs/development/api-audit.md` for the current core/FFI surface, proposed shape, and issues to address.

## Python 

### Python bindings (uv)
```bash
uv venv
uv pip install -e "bindings/python"
```

### Build a Python wheel (uv)
```bash
uv build --wheel
```

### Tests
```bash
uv pip install -e "bindings/python[dev]"
uv run --python .venv/bin/python pytest bindings/python/tests
```


## See also 

- [Contributing](../contributing.md)

## SDK compatibility

See [SDK compatibility](sdk-parity.md) for the required offline corpus, explicit SDK verification, and fixture refresh instructions.
