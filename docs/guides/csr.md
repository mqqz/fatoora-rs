# CSR Generation

This guide covers creating CSRs and private keys using the Rust core and CLI.

## Rust
=== "Rust"
    ```rust
    --8<-- "fatoora-core/examples/csr.rs:example"
    ```

=== "Python"
    ```python
    --8<-- "bindings/python/examples/csr.py:example"
    ```

=== "C/C++"
    ```c
    --8<-- "bindings/c/examples/csr.c:example"
    ```

## Notes
- `CsrProperties::parse_csr_config` expects a properties file with keys:
  `csr.common.name`, `csr.serial.number`, `csr.organization.identifier`,
  `csr.organization.unit.name`, `csr.organization.name`, `csr.country.name`,
  `csr.invoice.type`, `csr.location.address`, and `csr.industry.business.category`.
- Output includes the CSR plus its private key. Choose PEM or base64 DER depending on your target
  workflow.

See also: [CSR Reference](../reference/csr.md)
