# QR

ZATCA QR payload generation and accessors.

## Access QR

??? note "QR payload"
    Read the base64 TLV payload from a signed invoice.

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

    !!! info "Args"
        - `signed`: signed invoice handle.

    !!! info "Returns"
        - `string`: base64 TLV payload.

## Errors

!!! warning "Errors"
    - `QrCodeError` covers missing fields, TLV length overflow, or XML extraction failures.

## Behavior

!!! note "Behavior"
    - QR payloads use TLV tags 1-5 for seller + totals, and tags 6-9 for hash/signature data when present.
    - The base64-encoded payload must be 700 characters or fewer.

See also: [QR Guide](../guides/qr.md)
