# Invoice Signing

Signing helpers and signature metadata.

## Symbols

=== "Rust"
    - `InvoiceSigner::from_pem(cert_pem: &str, key_pem: &str) -> Result<InvoiceSigner, SigningError>`
    - `InvoiceSigner::from_der(cert_der: &[u8], key_der: &[u8]) -> Result<InvoiceSigner, SigningError>`
    - `FinalizedInvoice::sign(self, signer: &InvoiceSigner) -> Result<SignedInvoice, SigningError>`
    - `SignedInvoice::xml(&self) -> &str`
    - `SignedInvoice::to_xml_base64(&self) -> String`
    - `SignedInvoice::qr_code(&self) -> &str`
    - `SignedInvoice::invoice_hash(&self) -> &str`
    - `SignedInvoice::hash_base64(&self) -> Result<String, SigningError>`
    - `SignedInvoice::signature(&self) -> &str`
    - `SignedInvoice::public_key(&self) -> &str`
    - `SignedInvoice::zatca_key_signature(&self) -> Option<&str>`
    - `SignedProperties::signed_props_hash(&self) -> &str`
    - `invoice_hash_base64_from_xml_str(xml: &str) -> Result<String, SigningError>`

=== "Python"
    - `Signer.from_pem(cert_pem: str, key_pem: str) -> Signer`
    - `Signer.from_der(cert_der: bytes, key_der: bytes) -> Signer`
    - `Invoice.sign(signer: Signer) -> SignedInvoice`
    - `SignedInvoice.xml() -> str`
    - `SignedInvoice.xml_base64() -> str`
    - `SignedInvoice.qr() -> str`
    - `SignedInvoice.invoice_hash() -> str`
    - `SignedInvoice.hash_base64() -> str`
    - `SignedInvoice.signature() -> str`
    - `SignedInvoice.public_key() -> str`
    - `SignedInvoice.zatca_key_signature() -> Optional[str]`
    - `SignedInvoice.signed_props_hash() -> str`
    - `SignedInvoice.cert_hash() -> str`
    - `SignedInvoice.signing_time() -> str`

=== "C (FFI)"
    - `fatoora_signer_from_pem(cert_pem: const char*, key_pem: const char*) -> FfiResult_FfiSigner`
    - `fatoora_signer_from_der(cert_der: const uint8_t*, cert_len: uintptr_t, key_der: const uint8_t*, key_len: uintptr_t) -> FfiResult_FfiSigner`
    - `fatoora_invoice_sign(invoice: FfiFinalizedInvoice*, signer: FfiSigner*) -> FfiResult_FfiSignedInvoice`
    - `fatoora_signed_invoice_xml(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_xml_base64(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_qr(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_hash(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_hash_base64(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_signature(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_public_key(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_zatca_key_signature(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_signed_props_hash(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_cert_hash(signed: FfiSignedInvoice*) -> FfiResult_FfiString`
    - `fatoora_signed_invoice_signing_time(signed: FfiSignedInvoice*) -> FfiResult_FfiString`

## Types and helpers
- `SigningError` covers XML parsing, canonicalization, and certificate/key errors.
- `SignedProperties` exposes invoice hash, signature, public key, certificate hash, signed props
  hash, signing time, issuer/serial, and optional ZATCA key signature.

## Notes
- `SignedProperties::signing_time` is in `YYYY-MM-DDTHH:MM:SS` format (UTC).
- Invoice hashes are computed from canonicalized XML, excluding signature fields.

See also: [Invoice Signing Guide](../guides/invoice-signing.md)
