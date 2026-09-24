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

## Response receipt and acceptance

The three invoice methods return a response when HTTP status is 2xx and the body
can be decoded. Call `ensure_accepted()` to require acceptance of the invoked
operation. For compliance, acceptance means that the compliance check passed.

Use `outcome()` to handle `Accepted`, `Rejected`, and `Unknown` yourself. Warnings
alone allow acceptance. Missing, unfamiliar, or contradictory evidence produces
`Unknown`; inspect the original status fields and validation messages.

For clearance, `cleared_invoice_base64()` preserves the returned field.
`cleared_invoice_xml()` decodes nonempty UTF-8 text, preserving whitespace; it
returns `None` when absent and an error for empty or invalid content, including NUL. Decoding
does not parse XML or verify a signature. Save the returned XML directly when
you need the gateway document. An accepted outcome does not guarantee that this
optional document is present or decodable.

Non-2xx invoice responses return structured errors with `http_status`, response
text, and parsed JSON when available. Python exposes these in `error.details`;
C exposes them through `fatoora_BindingError_details_json`.

## Notes

- `Config` and credentials must target the same environment (non-production, simulation, or
  production).
- Reporting and clearance APIs require production credentials; compliance checks use compliance
  credentials.
- Invoice responses use opaque handles with getters in C and Python. Credential
  endpoints return credential handles and retain their existing response rules.

See also: [API Client Reference](../reference/api-client.md)
