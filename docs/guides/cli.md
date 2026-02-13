# CLI

The CLI wraps the Rust core for common workflows like CSR generation, invoice signing, validation, QR generation, QR reading, and hashing.

## Examples

```bash
fatoora-rs-cli csr --csr-config csr.properties --generated-csr csr.pem --private-key key.pem --pem
fatoora-rs-cli sign --invoice invoice.xml --cert cert.pem --key key.pem --signed-invoice signed.xml
fatoora-rs-cli validate --invoice invoice.xml --xsd-path assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd
fatoora-rs-cli qr --invoice invoice.xml
fatoora-rs-cli qr --invoice signed.xml --fail-on-signed
fatoora-rs-cli qr-read --invoice signed.xml
fatoora-rs-cli generate-hash --invoice invoice.xml
```

## Notes
- `csr` writes CSR and key to stdout unless `--generated-csr`/`--private-key` are provided.
  Use `--pem` to output PEM; otherwise output is base64 DER.
- `sign` requires matching cert/key formats (`--cert-format` and `--key-format` must both be PEM or
  DER).
- `validate` uses the bundled UBL schema by default and accepts `--xsd-path` to override it.
- `qr` generates a QR payload:
  from finalized invoice XML, or by regenerating from signed invoice XML.
  Use `--fail-on-signed` to reject signed invoices.
- `qr-read` reads the existing embedded QR payload from a signed invoice XML.
- `generate-hash` prints a signed hash if the XML is signed, otherwise falls back to finalized XML.

See also: [Invoice Reference](../reference/invoice-model.md) and [Signing Reference](../reference/invoice-signing.md)
