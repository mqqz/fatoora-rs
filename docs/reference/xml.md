---
title: Invoice XML Parsing and Serialization Reference
description: Parse, serialize, and preserve ZATCA invoice XML with fatoority. Find input formats, return types, formatting options, and signed XML ownership rules.
---

# Invoice XML

Use these APIs to read invoice XML into an invoice model, serialize a finalized invoice, or retrieve the exact XML stored by a signed invoice. For a walkthrough, see [invoice signing](../guides/invoice-signing.md) or [validation](../guides/validation.md).

## Choose an operation

| Operation | Input | Result and behavior |
| --- | --- | --- |
| Parse finalized invoice | Complete invoice XML text or a file path | A finalized invoice with supported fields and calculated totals. Supplied supported amounts are checked against calculations. |
| Parse signed invoice | Complete signed invoice XML text or a file path | A signed invoice containing signature metadata and the exact supplied XML text. Parsing does not verify the signature. |
| Serialize finalized invoice | Finalized invoice | XML text with default two-space indentation. Serialization creates a document from the model; it is not a lossless XML editor. |
| Read signed XML | Signed invoice | Exact stored XML, without formatting changes. Newly signed invoices store the output of signing; imported invoices store the input text. |
| Take signed XML | Signed invoice | Exact stored XML and consumption of the invoice state. |
| Encode signed XML | Signed invoice | Base64 of the stored XML, suitable for APIs that require encoded invoice content. |

Text inputs contain XML, not Base64 or a filename. File variants take a local filesystem path and read its contents as text. Parsing can fail on malformed XML, unsupported or missing required fields, or inconsistent supplied amounts. File operations can also fail when the path cannot be read.

Parsing and serialization do not establish schema conformance, business-rule compliance, or invoice acceptance. Run [validation](invoice-validation.md) explicitly when needed.

<span id="signedinvoice"></span>
## Preserve signed XML

Keep returned signed XML unchanged when saving or submitting it. Do not pretty-print, normalize whitespace, or reconstruct it from invoice data. Reading metadata does not change the stored XML. For edits followed by signing, see [invoice signing](invoice-signing.md).

## Language reference

Choose your language for imports, exact calls, returns, and ownership behavior.

=== "Rust"

    Import parsing functions from `fatoora_core::invoice::xml::parse` and `XmlFormat` from `fatoora_core::invoice::xml`.

    **Parse XML**

    ```rust
    parse_finalized_invoice_xml(xml: &str) -> Result<FinalizedInvoice, ParseError>
    parse_finalized_invoice_xml_file(path: impl AsRef<Path>) -> Result<FinalizedInvoice, ParseError>
    parse_signed_invoice_xml(xml: &str) -> Result<SignedInvoice, ParseError>
    parse_signed_invoice_xml_file(path: impl AsRef<Path>) -> Result<SignedInvoice, ParseError>
    ```

    **Serialize finalized invoices**

    ```rust
    FinalizedInvoice::to_xml(&self) -> Result<String, InvoiceXmlError>
    FinalizedInvoice::to_xml_with_format(&self, format: XmlFormat) -> Result<String, InvoiceXmlError>
    ```

    `to_xml()` uses two spaces of indentation. Choose `XmlFormat::Compact` for compact output or `XmlFormat::Pretty { indent_char: ' ', indent_size: 4 }` for explicit indentation. These are inherent methods; no serialization trait import is needed. They borrow the invoice and return a new owned string.

    **Read signed invoices**

    ```rust
    SignedInvoice::xml(&self) -> &str
    SignedInvoice::into_xml(self) -> String
    SignedInvoice::to_xml_base64(&self) -> String
    ```

    `xml()` borrows stored XML for the invoice's lifetime. `into_xml()` consumes the invoice and transfers the stored string without copying. `to_xml_base64()` returns a new string and leaves the invoice available. Signed invoices have no formatting methods.

=== "Python"

    Import these functions and invoice types from `fatoora`.

    **Parse XML**

    ```python
    parse_finalized_invoice_xml(xml: str) -> FinalizedInvoice
    parse_finalized_invoice_xml_file(path: str) -> FinalizedInvoice
    parse_signed_invoice_xml(xml: str) -> SignedInvoice
    parse_signed_invoice_xml_file(path: str) -> SignedInvoice
    ```

    **Read XML**

    ```python
    FinalizedInvoice.xml() -> str
    FinalizedInvoice.to_xml() -> str
    SignedInvoice.xml() -> str
    SignedInvoice.to_xml() -> str
    SignedInvoice.into_xml() -> str
    SignedInvoice.to_xml_base64() -> str
    ```

    `to_xml()` is an alias for `xml()`. Finalized output uses the default formatting; signed output preserves stored text. String results are independent Python strings. `into_xml()` consumes signed invoice state; later reads fail, but `close()` remains safe. Other methods leave state available. Use context managers or `close()` for owned objects. Errors raise exceptions; see [errors](errors.md).

=== "JavaScript"

    Import `FinalizedInvoice` and `SignedInvoice` from `fatoority`. These operations are synchronous and throw an `Error` with a `BindingError` cause on failure.

    ```javascript
    const finalized = FinalizedInvoice.fromXml(xml);
    const signed = SignedInvoice.fromXml(signedXml);
    const unsignedText = finalized.xml();
    const signedText = signed.xml();
    const encoded = signed.toXmlBase64();
    const takenText = signed.intoXml();
    ```

    Both `fromXml` methods expect a string and return their named invoice object. Every XML accessor returns a string. `intoXml()` consumes the signed invoice state; subsequent access fails. `xml()` and `toXmlBase64()` leave it available. Read a file using your host environment before passing its text to `fromXml`; filesystem parsing methods are not exposed in this binding. Finalized formatting is fixed to the default; signed output is exact stored text.

=== "C#"

    Use `Fatoora`. Methods throw on failure. Use `using` to dispose owned invoice objects.

    ```csharp
    FinalizedInvoice FinalizedInvoice.FromXml(string value)
    FinalizedInvoice FinalizedInvoice.FromFile(string value)
    SignedInvoice SignedInvoice.FromXml(string value)
    SignedInvoice SignedInvoice.FromFile(string value)
    string FinalizedInvoice.Xml()
    string SignedInvoice.Xml()
    string SignedInvoice.IntoXml()
    string SignedInvoice.ToXmlBase64()
    ```

    `FromFile` takes a local path. Returned strings are independent managed values. `IntoXml()` consumes invoice state, so further reads fail; disposal remains safe. Other accessors preserve the object. Finalized formatting uses two-space indentation; signed output is exact stored text.

=== "Kotlin"

    Import `com.fatoora.FinalizedInvoice` and `com.fatoora.SignedInvoice`. Methods throw on failure. Close invoice objects with `use`.

    ```kotlin
    FinalizedInvoice.fromXml(value: String): FinalizedInvoice
    FinalizedInvoice.fromFile(value: String): FinalizedInvoice
    SignedInvoice.fromXml(value: String): SignedInvoice
    SignedInvoice.fromFile(value: String): SignedInvoice
    FinalizedInvoice.xml(): String
    SignedInvoice.xml(): String
    SignedInvoice.intoXml(): String
    SignedInvoice.toXmlBase64(): String
    ```

    `fromFile` takes a local path. XML results are independent strings. `intoXml()` consumes invoice state; later access fails and `close()` remains safe. Reading `xml()` or `toXmlBase64()` leaves the invoice available. Finalized output uses default two-space indentation; signed output is exact stored text.

=== "Java"

    Import `com.fatoora.FinalizedInvoice` and `com.fatoora.SignedInvoice`. Use try-with-resources to close invoice objects; methods throw on failure.

    ```java
    FinalizedInvoice FinalizedInvoice.fromXml(String value)
    FinalizedInvoice FinalizedInvoice.fromFile(String value)
    SignedInvoice SignedInvoice.fromXml(String value)
    SignedInvoice SignedInvoice.fromFile(String value)
    String FinalizedInvoice.xml()
    String SignedInvoice.xml()
    String SignedInvoice.intoXml()
    String SignedInvoice.toXmlBase64()
    ```

    Static `fromFile` methods take a local path. String results remain valid after the invoice is closed. `intoXml()` consumes signed state; later access fails, and closing remains safe. The other accessors preserve state. Finalized output uses two-space indentation; signed output is exact stored text.

=== "C"

    Include `fatoora.h`. All calls below return `FatooraStatus` and take `FatooraError **error` as their final argument. Check status before reading an output; free any returned error with `fatoora_error_free()`.

    **Parse XML**

    ```c
    FatooraStatus fatoora_finalized_invoice_from_xml(const char *value,
        FatooraFinalizedInvoice **out, FatooraError **error);
    FatooraStatus fatoora_finalized_invoice_from_file(const char *value,
        FatooraFinalizedInvoice **out, FatooraError **error);
    FatooraStatus fatoora_signed_invoice_from_xml(const char *value,
        FatooraSignedInvoice **out, FatooraError **error);
    FatooraStatus fatoora_signed_invoice_from_file(const char *value,
        FatooraSignedInvoice **out, FatooraError **error);
    ```

    `value` is a NUL-terminated UTF-8 XML string for `_from_xml`, or a local path for `_from_file`. Returned invoice handles are owned; release them with `fatoora_finalized_invoice_free()` or `fatoora_signed_invoice_free()`.

    **Read XML**

    ```c
    FatooraStatus fatoora_finalized_invoice_xml(const FatooraFinalizedInvoice *self,
        char **out, FatooraError **error);
    FatooraStatus fatoora_signed_invoice_xml(const FatooraSignedInvoice *self,
        char **out, FatooraError **error);
    FatooraStatus fatoora_signed_invoice_into_xml(FatooraSignedInvoice *self,
        char **out, FatooraError **error);
    FatooraStatus fatoora_signed_invoice_to_xml_base64(const FatooraSignedInvoice *self,
        char **out, FatooraError **error);
    ```

    Each output is owned NUL-terminated text; release it with `fatoora_string_free()`. `_xml` copies the result and preserves invoice state. `_into_xml` consumes signed invoice state; further reads fail, but the outer handle must still be freed. `_to_xml_base64` returns encoded text without consuming state. Finalized formatting uses two-space indentation; signed output is never reformatted.
