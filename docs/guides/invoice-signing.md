# Invoice Signing

How to sign UBL invoices with a CSID certificate and private key.

## Example

=== "Rust"
    ```rust
    --8<-- "fatoora-core/examples/invoice_signing.rs:example"
    ```

=== "Python"
    ```python
    --8<-- "bindings/python/examples/invoice_signing.py:example"
    ```

=== "C/C++"
    ```c
    --8<-- "bindings/c/examples/invoice_signing.c:example"
    ```

## Notes
- Signed invoice metadata (signature/public key/signed props hashes) are exposed as getters.
- Prefer string-based XML inputs; the library does not read files for you.

See also: [Invoice Signing Reference](../reference/invoice-signing.md)
