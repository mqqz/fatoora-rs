# QR

## Types
- `QrCodeError` is returned when required fields are missing, TLV limits are exceeded, or XML
  extraction fails.
- `QrPayload` builds the ZATCA TLV payload from invoice data or signed invoice metadata.
- `QrResult<T>` is a `Result<T, QrCodeError>` alias.

## Behavior
- QR payloads are encoded as TLV (tags 1-5 for seller info and totals; tags 6-9 for hash/signature
  metadata when present) and then base64 encoded. The encoded payload must be 700 characters or
  fewer.

See also: [QR Guide](../guides/qr.md)
