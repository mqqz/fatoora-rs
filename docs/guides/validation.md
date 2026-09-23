# Invoice Validation

Validation is explicit: each operation establishes only the guarantees below.

| Operation | Guarantee |
| --- | --- |
| Validated wrapper constructor or deserialization | Existing validation and normalization for that wrapper |
| `build()` | Selected field, range, and amount checks; computed totals |
| XML parsing | Supported fields, wrapper and builder checks, and modeled supplied amounts |
| XSD validation | Conformance to the bundled UBL schema |
| Explicit ZATCA validation | Both pinned SDK rule profiles and applicable local integrity checks, with stage coverage |
| Signing | Generates signature material |
| Parsing a signed invoice | Extracts signature material without verifying authenticity |

`FinalizedInvoice` does not imply full business-rule compliance. `SignedInvoice`
may come from parsing and does not prove that its signature was verified.
Use `validate_zatca_invoice_from_str` on original XML for the complete local
profile. Inspect `is_valid()` in Rust or `report["is_valid"]` in Python/JSON.
No local operation establishes remote acceptance or certificate issuer trust.

`CountryCode`, `CurrencyCode`, `InvoiceTimestamp`, `InvoiceDate`, and `VatId`
deserialize through their constructors. Normalization is the same as construction;
invalid values are rejected. `VatId` currently checks only that the trimmed value
is nonempty.

## Example

=== "Rust"
    ```rust
    --8<-- "fatoora-core/examples/validation.rs:example"
    ```

=== "Python"
    ```python
    --8<-- "bindings/python/examples/validation.py:example"
    ```

=== "C/C++"
    ```c
    --8<-- "bindings/c/examples/validation.c:example"
    ```

## Local ZATCA profile

The profile implements the SDK `238-R3.4.8` adaptations of CEN and Saudi rules:
105 CEN assertion sites and 152 Saudi sites. Validation uses original XML, with
no Java or SDK runtime. Pass the predecessor hash from invoice history; missing
context produces an incomplete report. The default clock is one UTC snapshot,
or supply `evaluated_at` for repeatable results.

=== "Python"
    ```python
    --8<-- "bindings/python/examples/zatca_validation.py:example"
    ```

Rust accepts `ZatcaValidationOptions`; C accepts the same fields as JSON and
returns an owned report string. See the [reference](../reference/invoice-validation.md)
for signatures and error handling. All APIs retain warnings. A document rejection
returns a report; an execution failure carries any partial report.

Standard invoices skip signature and QR checks under this SDK profile.
Simplified invoices check the embedded certificate's key, reference digests,
signature and QR fields. These checks establish local integrity only. The
[development guide](../development/business-rules.md) records stricter local
integrity policies where the SDK accepts inconsistent QR or signature metadata.

All 15 UBL schemas are embedded in the library and materialized privately during
schema compilation. Installed packages do not need the source checkout. Local
validation uses the same profile in every configured API environment.

See also: [Invoice Validation Reference](../reference/invoice-validation.md)
