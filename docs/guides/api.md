# ZATCA API Client

Using the `fatoora-core` API client for compliance, reporting, and clearance APIs.

## Example

=== "Rust"
    ```rust
    --8<-- "fatoora-core/examples/api.rs:example"
    ```

=== "Python"
    ```python
    --8<-- "bindings/python/examples/api.py:example"
    ```

=== "C/C++"
    ```c
    --8<-- "bindings/c/examples/api.c:example"
    ```

## Notes
- `Config` and credentials must target the same environment (non-production, simulation, or
  production).
- Reporting and clearance APIs require production credentials; compliance checks use compliance
  credentials.
- All endpoints return structured validation responses; in FFI/bindings these are opaque handles
  with getter functions (no JSON payloads).

See also: [API Client Reference](../reference/api-client.md)
