# XML

## Types and functions
- `InvoiceXml` wraps an `InvoiceView` and provides XML serialization via `quick_xml`.
- `InvoiceXmlError` reports serialization failures.
- `XmlFormat` controls output formatting (`Compact` or `Pretty { indent_char, indent_size }`).
- `ToXml` is implemented for invoice types and exposes `to_xml` and `to_xml_with_format`.

## Parsing
- `parse::ParseError` covers XML parsing failures and missing/invalid fields.
- `parse::parse_finalized_invoice_xml` parses a finalized invoice from an XML string.
- `parse::parse_signed_invoice_xml` parses a signed invoice from an XML string.

See also: [Validation Guide](../guides/validation.md)
