# Invoice Validation

## Types and functions
- `ValidationResult` is a `Result<(), XmlValidationError>` alias used by schema validation calls.
- `XmlValidationError` reports invalid schema paths, schema parser errors, XML parse failures, and
  schema validation errors.
- `validate_xml_invoice_from_str(xml, config)` validates an invoice XML string against the UBL
  schema specified by `config`.

## Behavior
- Validation loads the schema from `Config::xsd_ubl_path` and uses libxml's schema validation.
- The environment only affects schema selection if you point the config to different XSDs.

See also: [Invoice Validation Guide](../guides/validation.md)
