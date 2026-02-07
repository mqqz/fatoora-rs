# Python Bindings

The Python package wraps the `fatoora-ffi` shared library via `cffi`.

## Notes
- Errors are raised as typed exceptions mapped from FFI error codes (see `FfiErrorKind`).
- Modules mirror the Rust core layout: `fatoora.config`, `fatoora.csr`, `fatoora.invoice`, and `fatoora.sign`.
- Invoice builder timestamps are strings in ZATCA ISO UTC format (`YYYY-MM-DDTHH:MM:SSZ`), and
  country/currency codes are validated strings.


## Signed Invoice Metadata
`SignedInvoice` exposes additional getters for auditing/debugging:
- `signature()`
- `public_key()`
- `cert_hash()`
- `signed_props_hash()`
- `signing_time()`

`signing_time()` returns a string in `YYYY-MM-DDTHH:MM:SS` (UTC).

## Example

```python
--8<-- "bindings/python/examples/python_bindings.py:example"
```

See also: [C/C++ Bindings](c.md)
