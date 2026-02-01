# XML

Serialization and parsing helpers for invoice XML.

## Symbols

=== "Rust"
    - `ToXml::to_xml(&self) -> Result<String, InvoiceXmlError>`
    - `ToXml::to_xml_with_format(&self, format: XmlFormat) -> Result<String, InvoiceXmlError>`
    - `SignedInvoice::xml(&self) -> &str`
    - `XmlFormat::Compact` / `XmlFormat::Pretty { indent_char, indent_size }`
    - `parse_finalized_invoice_xml(xml: &str) -> Result<FinalizedInvoice, ParseError>`
    - `parse_finalized_invoice_xml_file(path: impl AsRef<Path>) -> Result<FinalizedInvoice, ParseError>`
    - `parse_signed_invoice_xml(xml: &str) -> Result<SignedInvoice, ParseError>`
    - `parse_signed_invoice_xml_file(path: impl AsRef<Path>) -> Result<SignedInvoice, ParseError>`

=== "Python"
    - `Invoice.xml() -> str`
    - `SignedInvoice.xml() -> str`
    - `parse_invoice_xml(xml: str) -> Invoice`
    - `parse_invoice_xml_file(path: str) -> Invoice`
    - `parse_signed_invoice_xml(xml: str) -> SignedInvoice`
    - `parse_signed_invoice_xml_file(path: str) -> SignedInvoice`

=== "C (FFI)"
    - `fatoora_invoice_to_xml(invoice: FfiFinalizedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_xml(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_parse_finalized_invoice_xml(xml: const char*) -> FfiResult_FfiFinalizedInvoice`
    - `fatoora_parse_finalized_invoice_xml_file(path: const char*) -> FfiResult_FfiFinalizedInvoice`
    - `fatoora_parse_signed_invoice_xml(xml: const char*) -> FfiResult_FfiSignedInvoice`
    - `fatoora_parse_signed_invoice_xml_file(path: const char*) -> FfiResult_FfiSignedInvoice`

## Types
- `InvoiceXml<T>` wraps an `InvoiceView` for serialization.
- `InvoiceXmlError` reports serialization failures.
- `ParseError` reports XML parsing failures and missing/invalid fields.

See also: [Validation Guide](../guides/validation.md)
