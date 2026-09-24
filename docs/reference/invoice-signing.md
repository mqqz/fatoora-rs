# Invoice Signing

See [C and C++ bindings](bindings/c.md) for ownership rules and text output.
The declarations below come from the generated headers. C++ exposes the same types
in namespace `fatoora` through `fatoora/Type.hpp` headers.

Signing helpers and signature metadata.

## InvoiceSigner / Signer

### `from_pem`

???+ note "Create signer from PEM"
    Create a signer from PEM-encoded certificate and private key.

    === "{{ lang.rust }}"
        ```rust
        InvoiceSigner::from_pem(cert_pem: &str, key_pem: &str) -> Result<InvoiceSigner, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        Signer.from_pem(cert_pem: str, key_pem: str) -> Signer
        ```

    === "{{ lang.c }}"
        ```c
        #include "Signer.h"

        fatoora_Signer_from_pem_result fatoora_Signer_from_pem(DiplomatStringView cert_pem, DiplomatStringView key_pem);
        ```

### `from_der`

???+ note "Create signer from DER"
    Create a signer from DER-encoded certificate and private key.

    === "{{ lang.rust }}"
        ```rust
        InvoiceSigner::from_der(cert_der: &[u8], key_der: &[u8]) -> Result<InvoiceSigner, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        Signer.from_der(cert_der: bytes, key_der: bytes) -> Signer
        ```

    === "{{ lang.c }}"
        ```c
        #include "Signer.h"

        fatoora_Signer_from_der_result fatoora_Signer_from_der(DiplomatU8View cert_der, DiplomatU8View key_der);
        ```

### `certificate_pem`

???+ note "Read signer certificate as PEM"

    === "{{ lang.rust }}"
        ```rust
        InvoiceSigner::certificate_pem(&self) -> Result<String, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        Signer.certificate_pem() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "Signer.h"

        fatoora_Signer_certificate_pem_result fatoora_Signer_certificate_pem(const Signer* self, DiplomatWrite* write);
        ```

### `certificate_der`

???+ note "Read signer certificate as DER"

    === "{{ lang.rust }}"
        ```rust
        InvoiceSigner::certificate_der(&self) -> Result<Vec<u8>, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        Signer.certificate_der() -> bytes
        ```

    === "{{ lang.c }}"
        ```c
        #include "Signer.h"

        fatoora_Signer_certificate_der_result fatoora_Signer_certificate_der(const Signer* self);
        ```

### `sign_xml`

```rust
InvoiceSigner::sign_xml(&self, xml: &str) -> Result<String, SigningError>
```

Signs pre-built XML and returns the signed XML string. This does not construct a
`SignedInvoice` or run its invoice-model parsing checks. The input is parsed and
serialized, so its original byte representation is not preserved. Keep the
returned signed XML unchanged. Signing does not establish invoice compliance.

See [signed XML ownership](xml.md#signedinvoice) for borrowed, copied, and
consuming access to `SignedInvoice` XML.

## FinalizedInvoice

### `sign`

???+ note "Sign finalized invoice"
    Sign finalized invoice XML and return a signed invoice.

    === "{{ lang.rust }}"
        ```rust
        FinalizedInvoice::sign(self, signer: &InvoiceSigner) -> Result<SignedInvoice, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        FinalizedInvoice.sign(signer: Signer) -> SignedInvoice
        ```

    === "{{ lang.c }}"
        ```c
        #include "Signer.h"

        fatoora_Signer_sign_result fatoora_Signer_sign(const Signer* self, FinalizedInvoice* invoice);
        ```

## SignedInvoice

### `xml`

???+ note "Get signed XML"

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

### `to_xml_base64`

???+ note "Get signed XML as Base64"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::to_xml_base64(&self) -> String
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.to_xml_base64() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_to_xml_base64_result fatoora_SignedInvoice_to_xml_base64(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `qr_code`

???+ note "Get QR payload"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::qr_code(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.qr_code() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_qr_code_result fatoora_SignedInvoice_qr_code(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `invoice_hash`

???+ note "Get invoice hash"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::invoice_hash(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.invoice_hash() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_invoice_hash_result fatoora_SignedInvoice_invoice_hash(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `hash_base64`

???+ note "Get invoice hash as Base64"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::hash_base64(&self) -> Result<String, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.hash_base64() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_hash_base64_result fatoora_SignedInvoice_hash_base64(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `signature`

???+ note "Get signature value"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::signature(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.signature() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_signature_result fatoora_SignedInvoice_signature(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `public_key`

???+ note "Get public key"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::public_key(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.public_key() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_public_key_result fatoora_SignedInvoice_public_key(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `zatca_key_signature`

???+ note "Get optional ZATCA key signature"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::zatca_key_signature(&self) -> Option<&str>
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.zatca_key_signature() -> Optional[str]
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_zatca_key_signature_result fatoora_SignedInvoice_zatca_key_signature(const SignedInvoice* self);
        ```

### `signed_props_hash`

???+ note "Get signed properties hash"

    === "{{ lang.rust }}"
        ```rust
        SignedProperties::signed_props_hash(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.signed_props_hash() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_signed_props_hash_result fatoora_SignedInvoice_signed_props_hash(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `cert_hash`

???+ note "Get certificate hash"

    === "{{ lang.python }}"
        ```python
        SignedInvoice.cert_hash() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_cert_hash_result fatoora_SignedInvoice_cert_hash(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `signing_time`

???+ note "Get signing timestamp"

    === "{{ lang.python }}"
        ```python
        SignedInvoice.signing_time() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_signing_time_result fatoora_SignedInvoice_signing_time(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `issuer`

???+ note "Get certificate issuer from signed properties"

    === "{{ lang.rust }}"
        ```rust
        SignedProperties::issuer(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.issuer() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_issuer_result fatoora_SignedInvoice_issuer(const SignedInvoice* self, DiplomatWrite* write);
        ```

### `serial`

???+ note "Get certificate serial from signed properties"

    === "{{ lang.rust }}"
        ```rust
        SignedProperties::serial(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.serial() -> str
        ```

    === "{{ lang.c }}"
        ```c
        #include "SignedInvoice.h"

        fatoora_SignedInvoice_serial_result fatoora_SignedInvoice_serial(const SignedInvoice* self, DiplomatWrite* write);
        ```

## `invoice_hash_base64_from_xml_str`

### hash from XML

???+ note "Compute invoice hash (Base64)"
    Compute invoice hash from XML and return it as Base64.

    === "{{ lang.rust }}"
        ```rust
        invoice_hash_base64_from_xml_str(xml: &str) -> Result<String, SigningError>
        ```

## Errors

!!! warning "Errors"
    - `SigningError` covers XML parsing, canonicalization, and certificate/key errors.

## Notes

!!! note "Notes"
    - `SignedProperties::signing_time` uses `YYYY-MM-DDTHH:MM:SS` format (UTC).
    - Invoice hashes are computed from canonicalized XML excluding signature fields.

See also: [Invoice Signing Guide](../guides/invoice-signing.md)
