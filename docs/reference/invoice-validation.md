# Invoice Validation

Schema validation for invoice XML.

## `validate_xml_invoice_from_str`

### `validate`

???+ note "Validate invoice XML"
    Validate invoice XML against the bundled UBL schema.

    === "{{ lang.rust }}"
        ```rust
        validate_xml_invoice_from_str(xml: &str, config: &Config) -> Result<(), XmlValidationError>
        ```

    === "{{ lang.python }}"
        ```python
        validate_xml_invoice_from_str(config: Config, xml: str) -> bool
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_validate_xml_invoice_from_str(FfiConfig* config, const char* xml);
        ```

## Behavior

!!! note "Behavior"
    - Validation uses the bundled UBL 2.1 schema under `fatoora-core/assets`.
    - Errors include schema parse failures, XML parse failures, and schema validation errors.

See also: [Invoice Validation Guide](../guides/validation.md)
