# Invoice Signing

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
        FfiResult_FfiSigner fatoora_signer_from_pem(const char* cert_pem, const char* key_pem);
        ```

    !!! info "Args / Returns"
        - Types are language-specific and shown in the active tab signature above.

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
        FfiResult_FfiSigner fatoora_signer_from_der(const uint8_t* cert_der, uintptr_t cert_len, const uint8_t* key_der, uintptr_t key_len);
        ```

    !!! info "Args / Returns"
        - Types are language-specific and shown in the active tab signature above.

### `certificate_pem`

???+ note "Read signer certificate as PEM"

    === "{{ lang.python }}"
        ```python
        Signer.certificate_pem() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signer_certificate_pem(FfiSigner* signer);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

### `certificate_der`

???+ note "Read signer certificate as DER"

    === "{{ lang.python }}"
        ```python
        Signer.certificate_der() -> bytes
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiBytes fatoora_signer_certificate_der(FfiSigner* signer);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

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
        FfiResult_FfiSignedInvoice fatoora_invoice_sign(FfiFinalizedInvoice* invoice, FfiSigner* signer);
        ```

    !!! info "Args / Returns"
        - Types are language-specific and shown in the active tab signature above.

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
        FfiResult_FfiString fatoora_signed_invoice_xml(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

### `to_xml_base64` / `xml_base64`

???+ note "Get signed XML as Base64"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::to_xml_base64(&self) -> String
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.xml_base64() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signed_invoice_xml_base64(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

### `qr_code` / `qr`

???+ note "Get QR payload"

    === "{{ lang.rust }}"
        ```rust
        SignedInvoice::qr_code(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        SignedInvoice.qr() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signed_invoice_qr(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

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
        FfiResult_FfiString fatoora_signed_invoice_hash(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

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
        FfiResult_FfiString fatoora_signed_invoice_hash_base64(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

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
        FfiResult_FfiString fatoora_signed_invoice_signature(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

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
        FfiResult_FfiString fatoora_signed_invoice_public_key(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

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
        FfiResult_FfiString fatoora_signed_invoice_zatca_key_signature(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

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
        FfiResult_FfiString fatoora_signed_invoice_signed_props_hash(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

### `cert_hash`

???+ note "Get certificate hash"

    === "{{ lang.python }}"
        ```python
        SignedInvoice.cert_hash() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signed_invoice_cert_hash(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

### `signing_time`

???+ note "Get signing timestamp"

    === "{{ lang.python }}"
        ```python
        SignedInvoice.signing_time() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signed_invoice_signing_time(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - Types are language-specific and shown in the active tab signature above.

## `invoice_hash_base64_from_xml_str`

### hash from XML

???+ note "Compute invoice hash (Base64)"
    Compute invoice hash from XML and return it as Base64.

    === "{{ lang.rust }}"
        ```rust
        invoice_hash_base64_from_xml_str(xml: &str) -> Result<String, SigningError>
        ```

    !!! info "Args / Returns"
        - Types are language-specific and shown in the active tab signature above.

## Errors

!!! warning "Errors"
    - `SigningError` covers XML parsing, canonicalization, and certificate/key errors.

## Notes

!!! note "Notes"
    - `SignedProperties::signing_time` uses `YYYY-MM-DDTHH:MM:SS` format (UTC).
    - Invoice hashes are computed from canonicalized XML excluding signature fields.

See also: [Invoice Signing Guide](../guides/invoice-signing.md)
