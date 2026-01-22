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
  `assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd`.
- The environment only affects validation if you choose a different schema per environment.

See also: [Invoice Validation Reference](../reference/invoice-validation.md)
