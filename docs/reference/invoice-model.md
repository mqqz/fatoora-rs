# Invoice Model

Core data types for building invoices.

## Builders and views
- `RequiredInvoiceFields` holds the minimum set of inputs needed to build an invoice (type, IDs,
  timestamps, currency, previous hash, counter, seller, line items, payment means, VAT category).
- `InvoiceBuilder` lets you add optional fields (buyer, note, allowance/charge, flags) and then
  `build()` a validated invoice.
- `FinalizedInvoice` stores validated invoice data plus computed totals and supports hashing and
  XML serialization.
- `SignedInvoice` wraps a finalized invoice with signed XML, QR payload, and signature metadata.
- `InvoiceView` is the common read-only interface (`data`, `totals`, `qr_code`) used by XML
  serialization.

## Domain types
- `InvoiceType` and `InvoiceSubType` define whether the invoice is tax/prepayment/credit/debit and
  whether it is simplified or standard.
- `VatCategory` represents VAT category for line items (standard, zero, exempt, out of scope).
- `Address` uses `isocountry::CountryCode` for ISO country codes and holds postal fields.
- `Party`, `Seller`, and `Buyer` model the trading parties with validated IDs and address data.
- `VatId` validates VAT identifiers; `OtherId` stores additional IDs with optional scheme IDs.
- `InvoiceNote` stores a localized note (language + text).
- `OriginalInvoiceRef` links credit/debit notes to the original invoice.

## Line items and totals
- `LineItem` is an invoice line with quantity, unit, pricing, VAT, and computed totals.
- `LineItemFields` computes totals from quantity and unit price.
- `LineItemTotalsFields` accepts a provided total amount and derives VAT.
- `LineItemPartsFields` accepts full parts and validates totals for consistency.
- `LineItems` is a `Vec<LineItem>` alias used by the builder.
- `InvoiceData` is the core invoice model backing `FinalizedInvoice`/`SignedInvoice`.
- `InvoiceTotalsData` contains aggregated totals (line extension, tax, allowance, charge).

## Validation types
- `InvoiceError` covers invoice-level validation and missing/invalid identifiers.
- `ValidationError` holds a list of `ValidationIssue` values.
- `ValidationIssue` points to the field, validation kind, and optional line item index.
- `InvoiceField` enumerates the validated invoice fields.
- `ValidationKind` indicates why a field failed validation (missing, empty, mismatch, etc.).

See also: [CLI Guide](../guides/cli.md) and [Python Bindings Guide](../guides/python-bindings.md)
