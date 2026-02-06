# Invoice Signing

Signing helpers and signature metadata.

## Signer

??? note "Create from PEM"
    Create a signer from PEM-encoded certificate and private key strings.

    === "{{ lang.rust }}"
        ```rust
        InvoiceSigner::from_pem(cert_pem: &str, key_pem: &str) -> Result<InvoiceSigner, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        Signer.from_pem(cert_pem: str, key_pem: str) -> Signer
        Signer.certificate_pem() -> str
        Signer.certificate_der() -> bytes
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiSigner fatoora_signer_from_pem(const char* cert_pem, const char* key_pem);
        FfiResult_FfiString fatoora_signer_certificate_pem(FfiSigner* signer);
        FfiResult_FfiBytes fatoora_signer_certificate_der(FfiSigner* signer);
        ```

    !!! info "Args"
        - `cert_pem`: certificate in PEM format.
        - `key_pem`: private key in PEM format.

    !!! info "Returns"
        - `Signer`: ready to sign invoices.

    !!! warning "Errors"
        - `SigningError`: invalid PEM, key/cert mismatch, or parsing failures.

??? note "Create from DER"
    Create a signer from DER-encoded certificate and private key bytes.

    === "{{ lang.rust }}"
        ```rust
        InvoiceSigner::from_der(cert_der: &[u8], key_der: &[u8]) -> Result<InvoiceSigner, SigningError>
        ```

    === "{{ lang.python }}"
        ```python
        Signer.from_der(cert_der: bytes, key_der: bytes) -> Signer
        Signer.certificate_pem() -> str
        Signer.certificate_der() -> bytes
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiSigner fatoora_signer_from_der(const uint8_t* cert_der, uintptr_t cert_len, const uint8_t* key_der, uintptr_t key_len);
        FfiResult_FfiString fatoora_signer_certificate_pem(FfiSigner* signer);
        FfiResult_FfiBytes fatoora_signer_certificate_der(FfiSigner* signer);
        ```

    !!! info "Args"
        - `cert_der`: certificate bytes in DER format.
        - `key_der`: private key bytes in DER format.

    !!! info "Returns"
        - `Signer`: ready to sign invoices.

    !!! warning "Errors"
        - `SigningError`: invalid DER, key/cert mismatch, or parsing failures.

## Finalized Invoice

??? note "Sign"
    Signs the finalized invoice XML and returns a signed invoice.

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

    !!! info "Args"
        - `signer`: signer created from PEM/DER certificate + private key.

    !!! info "Returns"
        - `SignedInvoice`: signed XML plus metadata.

    !!! warning "Errors"
        - `SigningError`: XML parsing, canonicalization, or crypto failures.

## Signed Invoice

??? note "XML"
    Return the signed invoice XML string.

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
        - `string`: signed invoice XML.

??? note "XML (Base64)"
    Return the signed invoice XML as Base64.

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
        - `string`: Base64-encoded signed XML.

??? note "QR Code"
    Return the embedded QR payload.

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
        - `string`: QR payload.

??? note "Invoice Hash"
    Return the invoice hash string (canonicalized XML).

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
        - `string`: invoice hash.

??? note "Invoice Hash (Base64)"
    Return the invoice hash as Base64.

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
        - `string`: Base64-encoded invoice hash.

    !!! warning "Errors"
        - `SigningError`: canonicalization or encoding failures.

??? note "Signature"
    Return the signature value.

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
        - `string`: signature value.

??? note "Public Key"
    Return the public key from the signing certificate.

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
        - `string`: public key.

??? note "ZATCA Key Signature"
    Return the optional ZATCA key signature.

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
        - `string | null`: ZATCA key signature if present.

??? note "Signed Properties Hash"
    Return the signed properties hash.

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
        - `string`: signed properties hash.

??? note "Certificate Hash"
    Return the certificate hash.

    === "{{ lang.python }}"
        ```python
        SignedInvoice.cert_hash() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signed_invoice_cert_hash(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - `string`: certificate hash.

??? note "Signing Time"
    Return the signing timestamp in UTC.

    === "{{ lang.python }}"
        ```python
        SignedInvoice.signing_time() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signed_invoice_signing_time(FfiSignedInvoice* signed);
        ```

    !!! info "Returns"
        - `string`: UTC timestamp in `YYYY-MM-DDTHH:MM:SS` format.

## Helpers

??? note "Hash from XML (Base64)"
    Compute the invoice hash from an XML string and return it as Base64.

    === "{{ lang.rust }}"
        ```rust
        invoice_hash_base64_from_xml_str(xml: &str) -> Result<String, SigningError>
        ```

    !!! info "Args"
        - `xml`: invoice XML string.

    !!! info "Returns"
        - `string`: Base64-encoded invoice hash.

    !!! warning "Errors"
        - `SigningError`: XML parsing or canonicalization failures.

## Errors
- `SigningError` covers XML parsing, canonicalization, and certificate/key errors.

## Notes
- `SignedProperties::signing_time` is in `YYYY-MM-DDTHH:MM:SS` format (UTC).
- Invoice hashes are computed from canonicalized XML, excluding signature fields.

See also: [Invoice Signing Guide](../guides/invoice-signing.md)
