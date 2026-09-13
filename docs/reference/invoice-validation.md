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
    - XML parsing disables recovery: malformed XML is rejected rather than repaired.

See also: [Invoice Validation Guide](../guides/validation.md)

## Validation reports (Rust)

`validate_xml_invoice_report_from_str(xml, config)` returns
`Result<ValidationReport, XmlValidationError>` and runs only XSD validation.
The existing Rust, C, and Python validation APIs keep their current return types.

```rust
use fatoora_core::config::Config;
use fatoora_core::invoice::validation::{
    validate_xml_invoice_report_from_str, ValidationLayer,
};

fn example(xml: &str) -> Result<(), Box<dyn std::error::Error>> {
    let report = validate_xml_invoice_report_from_str(xml, &Config::default())?;
    assert_eq!(report.layers_checked, vec![ValidationLayer::Xsd]);
    for issue in &report.issues {
        println!("{}: {} ({:?})", issue.code, issue.message, issue.location);
    }
    if report.has_errors() {
        // Handle schema violations.
    }
    Ok(())
}
```

- `layers_checked` lists completed layers, including layers that found errors.
  An absent layer makes no claim. An empty report does not imply compliance.
- Each finding has `layer`, `code`, `severity`, `message`, and optional `location`.
- Severities are `Warning` and `Error`; backend fatal diagnostics become errors.
- Codes are stable library-owned identifiers. Message wording is not stable.
  Field codes are `FIELD_REQUIRED`, `FIELD_EMPTY`, `FIELD_INVALID_FORMAT`,
  `FIELD_OUT_OF_RANGE`, and `FIELD_MISMATCH`. Schema findings use `XSD_INVALID`.
  Official business-rule codes are reserved for implementations of those rules.
- Field locations use model paths such as `line_items[0].quantity` with zero-based
  indices. XML locations use one-based line and optional column numbers. Missing
  locations remain `None`; XPath locations are not inferred.
- Schema violations return `Ok(report)` with errors. Schema setup failures and
  malformed XML return `Err`, because XSD validation did not complete.
- `BusinessRules` and `Signature` are reserved layer variants; current report
  producers never list them. XSD validation also does not run builder checks.

Convert a builder `ValidationError` with `ValidationReport::from(&error)`, or an
individual `ValidationIssue` with `ValidationFinding::from(&issue)`. These
conversions preserve existing error APIs and do not execute additional checks.
Existing structured supplied/expected amounts remain available on the original
issue and are included in the finding message when present.
