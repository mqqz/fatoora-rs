# Invoice Model

Core data types for building invoices.

## Builders and views
- `InvoiceBuilder` starts with the invoice type and uses setters to supply required fields (IDs,
  timestamps, currency, previous hash, counter, seller, line items, payment means, VAT category).
  It then `build()`s a validated invoice.
- `FinalizedInvoice` stores validated invoice data plus computed totals and supports hashing and
  XML serialization.
- `SignedInvoice` wraps a finalized invoice with signed XML, QR payload, and signature metadata.
- `InvoiceView` is the common read-only interface (`data`, `totals`, `qr_code`) used by XML
  serialization.

## Domain types
- `InvoiceType` and `InvoiceSubType` define whether the invoice is tax/prepayment/credit/debit and
  whether it is simplified or standard.
- `VatCategory` represents VAT category for line items (standard, zero, exempt, out of scope).
- `Address` uses the crate-owned `CountryCode` string wrapper (validated ISO-3166) and holds
  postal fields.
- `Party`, `Seller`, and `Buyer` model the trading parties with validated IDs and address data.
- `VatId` validates VAT identifiers; `OtherId` stores additional IDs with optional scheme IDs.
- `InvoiceNote` stores a localized note (language + text).
- `OriginalInvoiceRef` links credit/debit notes to the original invoice.

## Line items and totals
- `LineItem` is an invoice line with quantity, unit, pricing, VAT, and computed totals.
- `LineItems` is a `Vec<LineItem>` alias used by the builder.
- `InvoiceData` is the core invoice model backing `FinalizedInvoice`/`SignedInvoice`, including
  string-validated `InvoiceTimestamp` (ZATCA ISO UTC `YYYY-MM-DDTHH:MM:SSZ`) and `CurrencyCode`.
- `InvoiceTotalsData` contains aggregated totals (line extension, tax, allowance, charge).

## Validation types
- `InvoiceError` covers invoice-level validation and missing/invalid identifiers.
- `ValidationError` holds a list of `ValidationIssue` values.
- `ValidationIssue` points to the field, validation kind, and optional line item index.
- `InvoiceField` enumerates the validated invoice fields.
- `ValidationKind` indicates why a field failed validation (missing, empty, mismatch, etc.).

See also: [CLI Guide](../guides/cli.md) and [Python Bindings Guide](../guides/python-bindings.md)
