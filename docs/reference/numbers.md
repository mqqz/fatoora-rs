# Decimal numbers and rounding

Invoice numeric values use `fatoora_core::Decimal`, a crate-owned type. Construct
values from decimal strings or integers. Floating-point conversions are not part
of the API.

```rust
use fatoora_core::{Decimal, invoice::{LineItem, VatCategory}};

let item = LineItem::new(
    "Item", Decimal::from(3), "PCE", "0.3333".parse()?,
    Decimal::from(15), VatCategory::Standard,
)?;
assert_eq!(item.total_amount(), "1.00".parse()?);
```

## Representation

Accepted syntax is `[+-]digits[.digits]`, using ASCII digits. Whitespace,
exponents, separators, infinities and NaN are rejected. Parsing never rounds.
The range is a signed 96-bit coefficient with a scale from 0 through 28.
Values outside that range return `DecimalError::OutOfRange`.

Equality compares numeric values: `1.0` equals `1.00`. Display and JSON use
canonical decimal strings, without exponents or unnecessary trailing zeros.
Negative zero is displayed as `0`. XML monetary fields use two decimal places;
quantities and unit prices retain their supported precision.

Arithmetic uses checked signed 128-bit integer intermediates. If an intermediate
coefficient or the final decimal cannot be represented, calculation returns an
error. Precision is never reduced to make an intermediate fit.

## Calculation boundaries

The calculation contract follows section 10 and the field-specific decimal
constraints in the [ZATCA XML standard, May 2023](https://www.zatca.gov.sa/ar/E-Invoicing/SystemsDevelopers/Documents/20230519_ZATCA_Electronic_Invoice_XML_Implementation_Standard_%20vF.pdf).

- Line net: calculate quantity × unit price, then round half-up to two decimals.
- Calculated line VAT: calculate quantity × unit price × rate / 100, then round
  once to two decimals. Do not round the intermediate product first.
- Group lines by VAT category and rate. Sum their finalized line net amounts and
  apply the document discounts and charges assigned to that group.
- Category VAT: multiply that taxable base by its rate, divide by 100, then round
  half-up to two decimals. Document VAT is the sum of these category VAT amounts.
- Document totals use the finalized amounts. XML and QR rendering consume those
  totals without introducing another calculation stage.

For three lines of `0.03` at 15%, each calculated line VAT is `0.00`, while document
VAT is `0.01`. The regression suite checks this difference.

Rates must be between 0 and 100 with at most two decimal places. Supplied amounts
such as document discounts and charges must already have at most two decimals.
Nonstandard VAT categories require a zero rate. Negative invoice line values and
negative discounts/charges are rejected by the builder. Credit notes use positive
amounts with the appropriate document type. A supplied signed payable-rounding
adjustment is preserved exactly; it is not rounded during import.

The builder's document VAT category assigns its scalar discount and charge to one
matching category/rate group. If several rates match, building fails. XML imports
can resolve that rate from the adjustment's explicit tax category. Multiple
adjustment category/rate groups require a richer adjustment model and are rejected.

## Calculated and supplied values

`LineItem::new` calculates amounts. `from_totals` and `try_from_parts` validate
supplied amounts against those calculations exactly; they return `InvoiceError`
on a mismatch. Validation issues expose the supplied and expected values.

XML import preserves supplied line VAT. The May 2023 standard removed BR-KSA-50;
BR-KSA-51 still relates line gross to line net plus supplied VAT. Import validates
amount precision, the line net calculation, line gross when present, document
adjustments, supplied category subtotals and document totals. It preserves prepaid
amounts and payable-rounding adjustments and checks the payable equation.

This numeric validation covers the model's supported calculations. It does not
replace the complete ZATCA business-rule validator or add line allowances, line
charges or price-base quantities to the model.

## Bindings and migration

This changes Rust signatures, JSON numeric fields and the C ABI. Rebuild native
bindings and their callers together.

Python inputs accept `decimal.Decimal`, `str` or `int`; floats are rejected.
Numeric getters return `decimal.Decimal`.

```python
builder.add_line_item("Item", 3, "PCE", "0.3333", "15", VatCategory.STANDARD)
```

C inputs are required UTF-8 decimal strings (`const char*`). Numeric getters return
`FfiResult_FfiString`; callers must release successful values with
`fatoora_string_free`. The backing decimal library has no public ABI representation.

## Regression checks

`numeric_contract.rs` tests rounding boundaries, adjustments, category aggregation,
XML import and serialization. `decimal.rs` covers parsing and string serialization.
QR, FFI and Python tests check the same amounts at their respective boundaries.

For independent numeric-rule checks using an extracted official SDK:

```sh
ZATCA_SDK_ROOT=/path/to/sdk cargo test -p fatoora-core --test numeric_contract official_sdk_numeric_rules
```

That test runs both official Schematron stylesheets through the SDK's bundled
Saxon engine. It checks numeric-rule failures only; unrelated invoice requirements
and signing are outside this test. Without the environment variable, it reports
that the SDK check was skipped.
