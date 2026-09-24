# XML

See [C and C++ bindings](bindings/c.md) for ownership rules and text output.
The declarations below come from the generated headers. C++ exposes the same types
in namespace `fatoora` through `fatoora/Type.hpp` headers.

Serialization and parsing helpers for invoice XML.

## FinalizedInvoice serialization

Serialization methods are inherent on `FinalizedInvoice`; no trait import is
needed. Signed invoices expose stored XML through `xml()` and `into_xml()` and
have no formatting methods.

Migration: remove `ToXml` imports and replace `to_xml_pretty()` with `to_xml()`.

### `to_xml`

???+ note "Serialize to XML"
    Serialize a finalized invoice with the default two-space indentation.

    === "{{ lang.rust }}"
        ```rust
        FinalizedInvoice::to_xml(&self) -> Result<String, InvoiceXmlError>
        ```

    === "{{ lang.python }}"
        ```python
        # use FinalizedInvoice.xml()
        ```

    === "{{ lang.c }}"
        ```c
        #include "FinalizedInvoice.h"

        fatoora_FinalizedInvoice_xml_result fatoora_FinalizedInvoice_xml(const FinalizedInvoice* self, DiplomatWrite* write);
        ```

### `to_xml_with_format`

???+ note "Serialize with format"
    Convert to XML with explicit format option.

    === "{{ lang.rust }}"
        ```rust
        FinalizedInvoice::to_xml_with_format(&self, format: XmlFormat) -> Result<String, InvoiceXmlError>
        ```

    === "{{ lang.python }}"
        ```python
        # not exposed directly
        ```

    === "{{ lang.c }}"
        ```c
        /* not exposed directly */
        ```

## FinalizedInvoice

### `xml`

???+ note "Get finalized invoice XML"

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
        #include "FinalizedInvoice.h"

        fatoora_FinalizedInvoice_xml_result fatoora_FinalizedInvoice_xml(const FinalizedInvoice* self, DiplomatWrite* write);
        ```

## SignedInvoice

Migration: replace Rust `signed.to_xml()?` with `signed.xml()` for a borrow or
`signed.into_xml()` to take ownership. The C copying accessor was renamed from
`fatoora_SignedInvoice_xml` to `fatoora_SignedInvoice_xml`; rebuild C callers
and bindings against the matching header and library.

Imported signed invoices retain the exact supplied XML string. Newly signed
invoices retain the exact output of signing. Accessors never reformat it.
Parsing signed XML does not verify its signature.

Rust `xml()` borrows the stored string. C `to_xml` and Python `xml()` return
independent copies. C writes text into `DiplomatWrite`; release buffer writers with
`diplomat_buffer_write_destroy`.

### `xml`

???+ note "Get signed invoice XML"

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
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_xml_result fatoora_SignedInvoice_xml(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `into_xml`

Consume the signed invoice and return its exact stored XML. Rust transfers the
stored `String` without copying it. C transfers the result into an owned C string;
Python decodes that result into a Python string. C and Python clear the invoice
handle, so subsequent access returns an error and closing it remains safe.

```rust
SignedInvoice::into_xml(self) -> String
```

```c
#include "SignedInvoice.h"

fatoora_SignedInvoice_into_xml_result fatoora_SignedInvoice_into_xml(SignedInvoice* self, DiplomatWrite* write);
```

```python
SignedInvoice.into_xml() -> str
```

## `parse_finalized_invoice_xml` / `parse_finalized_invoice_xml_file`

### parse finalized invoice

???+ note "Parse finalized invoice XML"

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
        #include "FinalizedInvoice.h"

        fatoora_FinalizedInvoice_from_xml_result fatoora_FinalizedInvoice_from_xml(DiplomatStringView value);
        fatoora_FinalizedInvoice_from_file_result fatoora_FinalizedInvoice_from_file(DiplomatStringView value);
        ```

## `parse_signed_invoice_xml` / `parse_signed_invoice_xml_file`

### parse signed invoice

???+ note "Parse signed invoice XML"

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
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_from_xml_result fatoora_SignedInvoice_from_xml(DiplomatStringView value);
        fatoora_SignedInvoice_from_file_result fatoora_SignedInvoice_from_file(DiplomatStringView value);
        ```

## Types

!!! note "Types"
    - `XmlFormat` selects compact output or explicit indentation for finalized invoices.
    - `InvoiceXmlError` reports serialization failures.
    - `ParseError` reports XML parsing failures and missing/invalid fields.

See also: [Validation Guide](../guides/validation.md)
