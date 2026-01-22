# FFI Layer

Information about the C FFI layer and how bindings integrate with it.

## Topics
- API responses are opaque handles with getter functions (no JSON).
- Errors are returned as `FfiError` handles with `code` and `message` getters.
- Signed invoice metadata getters (signature/public key/signed props hashes/signing time).
- Module headers are available under `fatoora/` for grouping (e.g., `fatoora/config.h`, `fatoora/invoice.h`).

For contributor workflows (adding new FFI endpoints, macro usage, header regeneration), see
[FFI Workflow](../development/ffi-workflow.md).

See also: [Python Bindings Guide](../guides/python-bindings.md) and [C/C++ Bindings Guide](../guides/c-bindings.md)
