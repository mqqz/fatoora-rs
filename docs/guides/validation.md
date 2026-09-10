# Invoice Validation

Validation workflows for UBL invoices and schema checks.

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
  `fatoora-core/assets/schemas/UBL2.1/xsd/UBL-Invoice-2.1.xsd`, and no other schema can be
  substituted.
- The environment has no effect on validation.
- Schema validation temporarily uses `libxml2`. Switching to uppsala requires a published
  fix for inherited simple-content values and child-element rejection, verified by
  the regression tests in `fatoora-core/tests/validation.rs`.

See also: [Invoice Validation Reference](../reference/invoice-validation.md)
