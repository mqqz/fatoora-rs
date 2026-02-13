# QR

ZATCA QR payload generation and accessors.

## SignedInvoice

### `qr_code` / `qr` / `fatoora_signed_invoice_qr`

???+ note "Read QR payload"
    Read the Base64 TLV QR payload from a signed invoice.

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::qr_code(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.qr() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signed_invoice_qr(FfiSignedInvoice* signed);
        ```

    !!! info "Args / Returns"
        - Types are language-specific and shown in the active tab signature above.

## Errors

!!! warning "Errors"
    - `QrCodeError` covers missing fields, TLV length overflow, or XML extraction failures.

## Behavior

!!! note "Behavior"
    - QR payloads use TLV tags 1-5 for seller + totals, and tags 6-9 for hash/signature data when present.
    - The Base64-encoded payload must be 700 characters or fewer.

See also: [QR Guide](../guides/qr.md)
