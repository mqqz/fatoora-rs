# QR

ZATCA QR payload generation and accessors.

## Symbols

=== "Rust"
    - `QrCodeError` — missing fields, TLV length overflow, or XML extraction failures.
    - `QrResult<T>` — `Result<T, QrCodeError>`.
    - `QrPayload` — public type, constructed internally by invoice signing.
    - `SignedInvoice::qr_code(&self) -> &str` — base64 TLV payload.

=== "Python"
    - `SignedInvoice.qr() -> str` — base64 TLV payload.

=== "C (FFI)"
    - `fatoora_signed_invoice_qr(signed: FfiSignedInvoice*) -> FfiResult_FfiString`

## Behavior
- QR payloads use TLV tags 1-5 for seller + totals, and tags 6-9 for hash/signature data when
  present.
- The base64-encoded payload must be 700 characters or fewer.

See also: [QR Guide](../guides/qr.md)
