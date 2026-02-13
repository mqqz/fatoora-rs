# XML

Serialization and parsing helpers for invoice XML.

## ToXml (trait)

### to_xml

??? note "Serialize to compact XML"
    Convert an invoice type to XML.

    === "{{ lang.rust }}"
        ```rust
        ToXml::to_xml(&self) -> Result<String, InvoiceXmlError>
        ```

    === "{{ lang.python }}"
        ```python
        # use FinalizedInvoice.xml() or SignedInvoice.xml()
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_invoice_to_xml(FfiFinalizedInvoice* invoice);
        FfiResult_FfiString fatoora_signed_invoice_xml(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Rust: `Result<String, InvoiceXmlError>`.
        - Python: `str` via type methods.
        - C: `FfiResult_FfiString`.

### to_xml_with_format

??? note "Serialize with format"
    Convert to XML with explicit format option.

    === "{{ lang.rust }}"
        ```rust
        ToXml::to_xml_with_format(&self, format: XmlFormat) -> Result<String, InvoiceXmlError>
        ```

    === "{{ lang.python }}"
        ```python
        # not exposed directly
        ```

    === "{{ lang.c }}"
        ```c
        /* not exposed directly */
        ```

    !!! info "Args"
        - `format` (`XmlFormat`): compact or pretty output.

    !!! info "Returns"
        - Rust: `Result<String, InvoiceXmlError>`.

## FinalizedInvoice

### xml

??? note "Get finalized invoice XML"

    === "{{ lang.rust }}"
        ```rust
        FinalizedInvoice::to_xml(&self) -> Result<String, InvoiceXmlError>
        ```

    === "{{ lang.python }}"
        ```python
        FinalizedInvoice.xml() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_invoice_to_xml(FfiFinalizedInvoice* invoice);
        ```

    !!! info "Returns"
        - Rust: `Result<String, InvoiceXmlError>`.
        - Python: `str`.
        - C: `FfiResult_FfiString`.

## SignedInvoice

### xml

??? note "Get signed invoice XML"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::xml(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.xml() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signed_invoice_xml(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Rust: `&str`.
        - Python: `str`.
        - C: `FfiResult_FfiString`.

## parse_finalized_invoice_xml / parse_finalized_invoice_xml_file

### parse finalized invoice

??? note "Parse finalized invoice XML"

    === "{{ lang.rust }}"
        ```rust
        parse_finalized_invoice_xml(xml: &str) -> Result<FinalizedInvoice, ParseError>
        parse_finalized_invoice_xml_file(path: impl AsRef<Path>) -> Result<FinalizedInvoice, ParseError>
        ```

    === "{{ lang.python }}"
        ```python
        parse_finalized_invoice_xml(xml: str) -> FinalizedInvoice
        parse_finalized_invoice_xml_file(path: str) -> FinalizedInvoice
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml(const char* xml);
        FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml_file(const char* path);
        ```

    !!! info "Args"
        - `xml` (`&str` / `str` / `const char*`): XML content.
        - `path` (`impl AsRef<Path>` / `str` / `const char*`): XML file path.

    !!! info "Returns"
        - Rust: `Result<FinalizedInvoice, ParseError>`.
        - Python: `FinalizedInvoice`.
        - C: `FfiResult_FfiFinalizedInvoice`.

## parse_signed_invoice_xml / parse_signed_invoice_xml_file

### parse signed invoice

??? note "Parse signed invoice XML"

    === "{{ lang.rust }}"
        ```rust
        parse_signed_invoice_xml(xml: &str) -> Result<SignedInvoice, ParseError>
        parse_signed_invoice_xml_file(path: impl AsRef<Path>) -> Result<SignedInvoice, ParseError>
        ```

    === "{{ lang.python }}"
        ```python
        parse_signed_invoice_xml(xml: str) -> SignedInvoice
        parse_signed_invoice_xml_file(path: str) -> SignedInvoice
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml(const char* xml);
        FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml_file(const char* path);
        ```

    !!! info "Args"
        - `xml` (`&str` / `str` / `const char*`): XML content.
        - `path` (`impl AsRef<Path>` / `str` / `const char*`): XML file path.

    !!! info "Returns"
        - Rust: `Result<SignedInvoice, ParseError>`.
        - Python: `SignedInvoice`.
        - C: `FfiResult_FfiSignedInvoice`.

## Types

!!! note "Types"
    - `InvoiceXml<T>` wraps an `InvoiceView` for serialization.
    - `InvoiceXmlError` reports serialization failures.
    - `ParseError` reports XML parsing failures and missing/invalid fields.

See also: [Validation Guide](../guides/validation.md)
