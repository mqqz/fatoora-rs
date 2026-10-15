---
title: ZATCA invoice QR payload reference
description: Read the Base64 TLV QR payload from a signed invoice and understand its fields, size limits and validation behavior.
---

# QR payloads

Signing generates a Base64-encoded TLV payload for the invoice. Pass this text to a QR image renderer to display or print it; the library returns text, not a PNG or SVG.

## Payload contract

| Value | Meaning |
| --- | --- |
| Tags 1–5 | Seller name, VAT registration number, timestamp, total including VAT and VAT total |
| Tags 6–9 | Invoice hash and signature material, where applicable |
| Individual field size | At most 255 UTF-8 bytes during generation; Arabic characters can occupy multiple bytes |
| Encoded size | At most 700 Base64 characters during generation |

Reading a stored QR payload does not validate its contents or enforce the generation limits. Parsing signed XML extracts metadata without verifying authenticity. Use [local invoice validation](invoice-validation.md) to check the QR against the invoice and signature material.

## Read the payload

The getter takes no arguments and leaves the signed invoice usable.

=== "Rust"

    `SignedInvoice::qr_code(&self) -> &str` borrows the payload from the invoice. Copy with `.to_owned()` to keep it after dropping the invoice.

=== "Python"

    `SignedInvoice.qr_code() -> str` returns an independent string.

=== "JavaScript"

    `SignedInvoice.qrCode()` returns a string.

=== "C#"

    `SignedInvoice.QrCode()` returns a managed `string`.

=== "Kotlin"

    `SignedInvoice.qrCode(): String` returns a managed string.

=== "Java"

    `SignedInvoice.qrCode()` returns a `String`.

=== "C"

    `fatoora_signed_invoice_qr_code(invoice, &out, &error)` returns `FatooraStatus`. `invoice` is a live `const FatooraSignedInvoice *`; `out` is an owned `char *`. On success, release the payload with `fatoora_string_free(out)`. Release any error with `fatoora_error_free(error)`.

For a complete rendering workflow, see the [QR guide](../guides/qr.md).
