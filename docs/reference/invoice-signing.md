# Invoice Signing

## Types and functions
- `SigningError` wraps signing, certificate parsing, XML parsing, canonicalization, and hashing
  failures encountered during signing operations.
- `SignedProperties` contains the signed invoice metadata (invoice hash, signature, public key,
  certificate hash, signed properties hash, signing time, issuer/serial, and optional ZATCA key
  signature).
- `InvoiceSigner` builds a signer from DER/PEM certificate + key (`from_der`, `from_pem`) and can
  sign invoices or raw XML (`sign_xml`).
- `FinalizedInvoice::hash_base64`
- `SignedInvoice::hash_base64`
- `invoice_hash_base64_from_xml_str`
- `SignedInvoice::signature`
- `SignedInvoice::public_key`
- `SignedInvoice::signed_properties`

Note: `SignedProperties::signing_time` is a string in `YYYY-MM-DDTHH:MM:SS` format (UTC).

## Workflow
- For full Rust flows, build an invoice, call `FinalizedInvoice::hash_base64` (or `SignedInvoice::hash_base64`),
  then sign with `InvoiceSigner` to obtain a `SignedInvoice` with QR and signed XML.
- For XML-only flows, use `invoice_hash_base64_from_xml_str` and `InvoiceSigner::sign_xml` to avoid
  exposing libxml types in your public API.
- Invoice hashes are computed from canonicalized XML, so signature fields do not affect the hash.

See also: [Invoice Signing Guide](../guides/invoice-signing.md)
