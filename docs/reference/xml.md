# XML

Serialization and parsing helpers for invoice XML.

## Serialize

??? note "Serialize to XML"
    Convert invoice types to XML.

    === "{{ lang.rust }}"
        ```rust
        ToXml::to_xml(&self) -> Result<String, InvoiceXmlError>
        ToXml::to_xml_with_format(&self, format: XmlFormat) -> Result<String, InvoiceXmlError>
        SignedInvoice::xml(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        FinalizedInvoice.xml() -> str
        SignedInvoice.xml() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_invoice_to_xml(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_signed_invoice_xml(FfiSignedInvoice* signed);
        ```

    !!! info "Args"
        - `format`: compact or pretty XML format (Rust).
        - `invoice` / `signed`: invoice handles.

    !!! info "Returns"
        - `string`: XML string.

## Parse

??? note "Parse from XML"
    Parse XML into invoice handles.

    === "{{ lang.rust }}"
        ```rust
        parse_finalized_invoice_xml(xml: &str) -> Result<FinalizedInvoice, ParseError>
        parse_finalized_invoice_xml_file(path: impl AsRef<Path>) -> Result<FinalizedInvoice, ParseError>
        parse_signed_invoice_xml(xml: &str) -> Result<SignedInvoice, ParseError>
        parse_signed_invoice_xml_file(path: impl AsRef<Path>) -> Result<SignedInvoice, ParseError>
        ```

    === "{{ lang.python }}"
        ```python
        parse_finalized_invoice_xml(xml: str) -> FinalizedInvoice
        parse_finalized_invoice_xml_file(path: str) -> FinalizedInvoice
        parse_signed_invoice_xml(xml: str) -> SignedInvoice
        parse_signed_invoice_xml_file(path: str) -> SignedInvoice
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml(const char* xml);
        FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml_file(const char* path);
        FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml(const char* xml);
        FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml_file(const char* path);
        ```

    !!! info "Args"
        - `xml`: XML string.
        - `path`: path to XML file.

    !!! info "Returns"
        - `FinalizedInvoice` / `SignedInvoice`: parsed invoice handles.

## Types
- `InvoiceXml<T>` wraps an InvoiceView for serialization.
- `InvoiceXmlError` reports serialization failures.
- `ParseError` reports XML parsing failures and missing/invalid fields.

See also: [Validation Guide](../guides/validation.md)
