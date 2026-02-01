# Invoice Validation

Schema validation for invoice XML.

## Symbols

=== "Rust"
    - `validate_xml_invoice_from_str(xml: &str, config: &Config) -> Result<(), XmlValidationError>`
    - `ValidationResult` — type alias for the above result.
    - `XmlValidationError` — invalid XSD path, schema parse, XML parse, or schema validation errors.

=== "Python"
    - `validate_xml_str(config: Config, xml: str) -> bool` — raises `XmlError` on failure.

=== "C (FFI)"
    - `fatoora_validate_xml_str(config: FfiConfig*, xml: const char*) -> FfiResult_bool`
    - `FfiErrorKind::Xml` — returned on XML or schema failures.

## Behavior
- Validation uses the bundled UBL 2.1 schema under `fatoora-core/assets`.
- Errors include schema parse failures, XML parse failures, and schema validation errors.

See also: [Invoice Validation Guide](../guides/validation.md)
