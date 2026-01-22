# Errors

Error types used across the core library and CLI.

## Core errors
- `Error` is the top-level wrapper that converts from invoice, signing, QR, XML, validation, CSR,
  and API client errors.

## Invoice errors
- `InvoiceError` includes validation failures, invalid country/VAT formats, and missing buyer/seller
  identifiers.
- `ValidationError` wraps a list of `ValidationIssue` values.
- `ValidationIssue` identifies the field, validation kind, and optional line item index.
- `InvoiceField` enumerates validated invoice fields (IDs, line items, payment means, etc.).
- `ValidationKind` classifies issues (missing, empty, invalid format, out of range, mismatch).

## CSR errors
- `CsrError` reports property parsing failures, missing required keys, invalid subject/SAN,
  encoding issues, and CSR build errors.

## Signing errors
- `SigningError` wraps signing, XML parsing, canonicalization, and certificate/key parsing errors.

## Validation errors
- `XmlValidationError` reports invalid schema paths, schema parsing errors, XML parse failures, and
  schema validation errors.

## API client errors
- `ZatcaError` reports HTTP failures, invalid responses, unauthorized/server errors, and client
  state errors.
- `UnauthorizedResponse` and `ServerErrorResponse` represent error bodies returned by ZATCA.

See also: [Core Reference](core.md)
