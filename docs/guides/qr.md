# QR Codes

Generating QR payloads from finalized/signed invoices and reading embedded QR payloads from signed invoices.

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

=== "CLI"
    ```bash
    fatoora-rs-cli qr --invoice invoice.xml
    fatoora-rs-cli qr --invoice signed.xml
    fatoora-rs-cli qr --invoice signed.xml --fail-on-signed
    fatoora-rs-cli qr-read --invoice signed.xml
    ```

## Notes
- The QR payload is a base64-encoded TLV string. Tag ordering follows ZATCA (seller, VAT, timestamp,
  totals) and includes signing tags when available.

See also: [QR Reference](../reference/qr.md)
