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
- Validation uses the XSD path from `Config::xsd_ubl_path`. Use `Config::with_xsd_path` (or
  `Config.with_xsd_path` in Python) to point at a custom UBL schema.
- The environment only affects validation if you choose a different schema per environment.

See also: [Invoice Validation Reference](../reference/invoice-validation.md)
