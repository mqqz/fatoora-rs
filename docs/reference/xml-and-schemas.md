---
title: UBL XML and schema behavior
description: Understand bundled UBL 2.1 validation, XML hashing, decimal support and the limits of schema validation.
---

# XML and schemas

The library reads and writes UBL invoice XML and includes the UBL 2.1 invoice schema. Validation uses bundled resources and does not download schemas from locations supplied by an invoice. No SDK installation or network access is needed.

## Choose an operation

| Operation | Input | Result and guarantee |
| --- | --- | --- |
| [Parse XML](xml.md) | Invoice XML text | A supported invoice model with field and amount checks; not a complete compliance check |
| [Validate the schema](invoice-validation.md) | Original XML and configuration | Checks element structure, attributes and schema types |
| [Validate locally](invoice-validation.md#local-zatca-report) | Original XML, configuration and predecessor context | A report covering schema, business rules and applicable integrity checks |
| [Hash XML](xml.md) | Original XML text | Base64 invoice digest after invoice-specific exclusions and canonicalization |
| [Sign XML](invoice-signing.md) | XML, certificate and private key | Signed XML; signing alone does not establish compliance |

## Decimal values

The bundled schema's amount, measure, numeric and quantity fields accept XML decimal syntax without imposing a machine floating-point range. This preserves schema validation for large decimal values. An extension that directly uses `xs:decimal` can still encounter the schema engine's numeric capacity limit.

Invoice-model calculations and business-rule validation have separate precision and capacity limits. Passing schema validation does not mean a value can be calculated by the model. See [decimal numbers and rounding](numbers.md).

## Hashing and signed XML

Invoice hashing applies the invoice-specific exclusions and C14N 1.1 canonicalization before calculating the digest. It is not a hash of the raw file bytes. Keep the returned signed XML unchanged when storing or submitting it: formatting or rebuilding it can change signature-relevant content.

Parsing a signed invoice reads its embedded signature metadata; it does not verify the signature, certificate issuer trust or remote acceptance. Use the validation report to determine which checks actually completed.
