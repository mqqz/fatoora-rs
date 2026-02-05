# Invoice Validation

Schema validation for invoice XML.

## Validate XML

??? note "Validate XML"
    Validate invoice XML against the bundled UBL schema.

    === "{{ lang.rust }}"
        ```rust
        validate_xml_invoice_from_str(xml: &str, config: &Config) -> Result<(), XmlValidationError>
        ```

    === "{{ lang.python }}"
        ```python
        validate_xml_str(config: Config, xml: str) -> bool
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_bool fatoora_validate_xml_str(FfiConfig* config, const char* xml);
        ```

    !!! info "Args"
        - `config`: environment config handle.
        - `xml`: invoice XML string.

    !!! info "Returns"
        - Rust: Ok(()) on success, XmlValidationError on failure.
        - Python: True on success, raises XmlError on failure.
        - C: ok=true on success, error set on failure.

## Behavior

!!! note "Behavior"
    - Validation uses the bundled UBL 2.1 schema under fatoora-core/assets.
    - Errors include schema parse failures, XML parse failures, and schema validation errors.

See also: [Invoice Validation Guide](../guides/validation.md)
