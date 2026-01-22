# Python Bindings

The Python package wraps the `fatoora-ffi` shared library via `cffi`.

## Notes
- Errors are raised as typed exceptions mapped from FFI error codes (see `FfiErrorKind`).
- Modules mirror the Rust core layout: `fatoora.config`, `fatoora.csr`, `fatoora.invoice`, and `fatoora.sign`.

## Signed Invoice Metadata
`SignedInvoice` exposes additional getters for auditing/debugging:
- `signature()`
- `public_key()`
- `cert_hash()`
- `signed_props_hash()`
- `signing_time()`

## Example

```python
--8<-- "bindings/python/examples/python_bindings.py:example"
```

See also: [FFI Reference](../reference/ffi.md)
