# Invoice Validation

Validation is explicit: each operation establishes only the guarantees below.

| Operation | Guarantee |
| --- | --- |
| Validated wrapper constructor or deserialization | Existing validation and normalization for that wrapper |
| `build()` | Selected field, range, and amount checks; computed totals |
| XML parsing | Supported fields, wrapper and builder checks, and modeled supplied amounts |
| XSD validation | Conformance to the bundled UBL schema |
| Signing | Generates signature material |
| Parsing a signed invoice | Extracts signature material without verifying authenticity |

`FinalizedInvoice` does not imply full business-rule compliance. `SignedInvoice`
may come from parsing and does not prove that its signature was verified.
Full business rules remain separate work; none of these operations establishes
complete ZATCA compliance.

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

## Notes
- Validation uses the bundled UBL schema at
  `assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd`.
- The environment only affects validation if you choose a different schema per environment.

See also: [Invoice Validation Reference](../reference/invoice-validation.md)
