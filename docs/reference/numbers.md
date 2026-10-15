---
title: Decimal numbers and invoice rounding
description: Exact decimal inputs, supported precision, VAT rounding and invoice total calculations in fatoority.
---

# Decimal numbers and rounding

Use decimal strings or integers for invoice amounts. Parsing never silently rounds an input.

## Representation

Accepted syntax is `[+-]digits[.digits]`, using ASCII digits. Whitespace,
exponents, separators, infinities and NaN are rejected. Parsing never rounds.
The range is a signed 96-bit coefficient with a scale from 0 through 28.
Values outside that range fail with an out-of-range error.

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
VAT is `0.01`.

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

Line-item construction calculates amounts. Importing supplied totals validates them
against those calculations exactly; mismatches return validation issues containing
the supplied and expected values.

XML import preserves supplied line VAT. The May 2023 standard removed BR-KSA-50;
BR-KSA-51 still relates line gross to line net plus supplied VAT. Import validates
amount precision, the line net calculation, line gross when present, document
adjustments, supplied category subtotals and document totals. It preserves prepaid
amounts and payable-rounding adjustments and checks the payable equation.

This numeric validation covers the model's supported calculations. It does not
replace the complete ZATCA business-rule validator or add line allowances, line
charges or price-base quantities to the model.


## Values in your language

=== "Rust"

    `fatoora_core::Decimal` accepts decimal strings through `parse()` and integers through `Decimal::from`. Parsing returns `DecimalError` on invalid syntax or range. Numeric getters return `Decimal`.

    ```rust
    let price: fatoora_core::Decimal = "0.3333".parse()?;
    ```

=== "Python"

    Inputs accept `decimal.Decimal`, `str`, or `int`. Both `float` and `bool` are rejected. Numeric getters return `decimal.Decimal`.

    ```python
    from decimal import Decimal
    price = Decimal("0.3333")
    ```

=== "JavaScript"

    Pass quantities, prices, rates and amounts as decimal strings, such as `"0.3333"`. Numeric getters return strings. Avoid converting financial values to `Number`, which can lose precision.

=== "C#"

    Pass quantities, prices, rates and amounts as invariant decimal strings, such as `"0.3333"`. Numeric getters return `string`. If formatting a `decimal`, use `CultureInfo.InvariantCulture`.

=== "Kotlin"

    Pass quantities, prices, rates and amounts as decimal strings. Numeric getters return `String`. Use `BigDecimal.toPlainString()` when converting a value; scientific notation is not accepted.

=== "Java"

    Pass quantities, prices, rates and amounts as decimal strings. Numeric getters return `String`. Use `BigDecimal.toPlainString()` when converting a value; scientific notation is not accepted.

=== "C"

    Inputs are NUL-terminated UTF-8 decimal strings, such as `"0.3333"`. Numeric getters return owned text through `char **out`; release it with `fatoora_string_free()`. Check the returned `FatooraStatus` before reading the output.
