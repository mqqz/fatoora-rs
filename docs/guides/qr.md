# QR Codes

Extracting and generating QR payloads from signed invoices.

## Example

=== "Rust"
    ```rust
    --8<-- "fatoora-core/examples/qr.rs:example"
    ```

=== "Python"
    ```python
    --8<-- "bindings/python/examples/qr.py:example"
    ```

=== "C/C++"
    ```c
    --8<-- "bindings/c/examples/qr.c:example"
    ```

## Notes
- The QR payload is a base64-encoded TLV string. Tag ordering follows ZATCA (seller, VAT, timestamp,
  totals) and includes signing tags when available.

See also: [QR Reference](../reference/qr.md)
