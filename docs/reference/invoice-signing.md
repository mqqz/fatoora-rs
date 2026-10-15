---
title: Invoice signing and signature metadata reference
description: Certificate and key requirements, signing methods, return values, ownership and signed invoice metadata for every supported language.
---

# Invoice signing reference

Create a signer from an X.509 certificate and an unencrypted secp256k1 private key in PKCS#8 format. Use it to sign a finalized invoice or existing XML. For a complete workflow, see the [signing guide](../guides/invoice-signing.md).

## Inputs and behavior

| Operation | Expected input | Result and behavior |
| --- | --- | --- |
| Create from PEM | Certificate PEM and private-key PEM text | A reusable signer; rejects invalid certificate/key encodings |
| Create from DER | Certificate DER bytes and private-key PKCS#8 DER bytes | A reusable signer with the same behavior as PEM construction |
| Export certificate | Live signer | Certificate as PEM text or DER bytes |
| Sign finalized invoice | A finalized invoice and a live signer | A signed invoice; consumes the finalized invoice's state |
| Sign existing XML | UBL invoice XML text | Signed XML text; preserves bytes outside the signing structures it owns. Re-signing requires the same certificate |
| Hash existing XML | XML text | Base64 invoice digest after invoice-specific exclusions and canonicalization |

Signer construction parses the certificate and key; it does not establish that they match, that the certificate is trusted, or that its dates are valid. Signing checks that the private key matches the certificate and rejects a mismatch. It does not run the complete invoice validator. Validate the resulting XML separately when you need a local compliance report.

Keep signed XML unchanged for storage and submission. Signing existing XML does not construct an invoice model or run all model-import checks.

## Signed invoice values

All getters below leave the signed invoice usable. Values extracted from imported signed XML are metadata, not proof of signature verification.

| Value | Returned content |
| --- | --- |
| XML | Original stored signed XML text |
| XML Base64 | Base64 of that stored XML text |
| QR code | Base64 TLV payload for rendering; see [QR reference](qr.md) |
| Invoice hash | Embedded invoice digest from signature metadata |
| Model hash | Recomputed hash of the underlying finalized model's serialization; **not an alias for the embedded hash** |
| Signature | Encoded invoice signature |
| Public key | Encoded public-key material |
| ZATCA key signature | Optional encoded certificate-signature material |
| Issuer / serial | Certificate issuer and serial from signed properties |
| Certificate hash | Encoded certificate digest |
| Signed properties hash | Encoded signed-properties digest |
| Signing time | UTC text in `YYYY-MM-DDTHH:MM:SS` format |

To hash a particular XML document, use the XML hash operation rather than the model hash getter. See [XML reference](xml.md) for parsing and consuming XML access.

## Methods by language

<span id="invoicesigner-signer"></span>
<span id="finalizedinvoice"></span>
<span id="signedinvoice"></span>
<span id="from_pem"></span>
<span id="from_der"></span>
<span id="certificate_pem"></span>
<span id="certificate_der"></span>
<span id="sign_xml"></span>
<span id="sign"></span>
<span id="xml"></span>
<span id="to_xml_base64"></span>
<span id="qr_code"></span>
<span id="invoice_hash"></span>
<span id="hash_base64"></span>
<span id="signature"></span>
<span id="public_key"></span>
<span id="zatca_key_signature"></span>
<span id="signed_props_hash"></span>
<span id="cert_hash"></span>
<span id="signing_time"></span>
<span id="issuer"></span>
<span id="serial"></span>
<span id="invoice_hash_base64_from_xml_str"></span>
<span id="hash-from-xml"></span>

=== "Rust"

    Import `InvoiceSigner`, `SigningError`, and `invoice_hash_base64_from_xml_str`
    from `fatoora_core::invoice::sign`.

    **Construct, export and sign**

    ```rust
    InvoiceSigner::from_pem(cert_pem: &str, key_pem: &str) -> Result<InvoiceSigner, SigningError>
    InvoiceSigner::from_der(cert_der: &[u8], key_der: &[u8]) -> Result<InvoiceSigner, SigningError>
    signer.certificate_pem() -> Result<String, SigningError>
    signer.certificate_der() -> Result<Vec<u8>, SigningError>
    signer.sign_xml(xml: &str) -> Result<String, SigningError>
    invoice.sign(signer: &InvoiceSigner) -> Result<SignedInvoice, SigningError>
    invoice_hash_base64_from_xml_str(xml: &str) -> Result<String, SigningError>
    ```

    `invoice.sign` takes a `FinalizedInvoice` by value. `SignedInvoice::xml`, `qr_code`, `invoice_hash`, `signature` and `public_key` return borrowed `&str`; `zatca_key_signature` returns `Option<&str>`. `to_xml_base64` returns `String`; `hash_base64` returns `Result<String, SigningError>`.

    Use `signed.signed_properties()` for `issuer()`, `serial()`, `cert_hash()`, `signed_props_hash()` and `signing_time()`, all borrowed `&str`. Copy borrowed strings to retain them after dropping the invoice. Failures expose `SigningError::kind()` and structured details through the shared error type.

=== "Python"

    | Call | Return |
    | --- | --- |
    | `Signer.from_pem(cert_pem: str, key_pem: str)` | `Signer` |
    | `Signer.from_der(cert_der: bytes, key_der: bytes)` | `Signer` |
    | `signer.certificate_pem()` / `certificate_der()` | `str` / `bytes` |
    | `signer.sign_xml(xml: str)` | `str` |
    | `finalized.sign(signer: Signer)` | `SignedInvoice`; consumes finalized state |
    | `invoice_hash_base64_from_xml_str(xml: str)` | `str` |

    `SignedInvoice` string getters are `xml()`, `to_xml_base64()`, `qr_code()`, `invoice_hash()`, `hash_base64()`, `signature()`, `public_key()`, `issuer()`, `serial()`, `cert_hash()`, `signed_props_hash()` and `signing_time()`. `zatca_key_signature()` returns `str | None`. Strings and bytes are independent copies. Use context managers or `close()` for owners; errors raise the typed exceptions in [errors](errors.md).

=== "JavaScript"

    | Call | Return |
    | --- | --- |
    | `Signer.fromPem(certPem: string, keyPem: string)` | `Signer` |
    | `Signer.fromDer(certDer: Array<number>, keyDer: Array<number>)` | `Signer` |
    | `signer.certificatePem()` | `string` |
    | `signer.certificateDer()` | `Bytes` |
    | `signer.signXml(xml: string)` | `string` |
    | `signer.sign(invoice: FinalizedInvoice)` | `SignedInvoice`; consumes invoice state |
    | `Xml.hash(xml: string)` | `string` |

    `SignedInvoice` text getters: `xml()`, `toXmlBase64()`, `qrCode()`, `invoiceHash()`, `hashBase64()`, `signature()`, `publicKey()`, `issuer()`, `serial()`, `certHash()`, `signedPropsHash()`, `signingTime()`. Each returns `string`. `zatcaKeySignature()` returns optional `Text`; read its `value()` to obtain text.

    Objects use garbage-collected cleanup. `Bytes.asSlice()` returns a copied number array. Native failures throw an `Error` with a `BindingError` in `error.cause`; see [error handling](errors.md).

=== "C#"

    | Call | Return |
    | --- | --- |
    | `Signer.FromPem(certPem: string, keyPem: string)` | `Signer` |
    | `Signer.FromDer(certDer: byte[], keyDer: byte[])` | `Signer` |
    | `signer.CertificatePem()` | `string` |
    | `signer.CertificateDer()` | `Bytes` |
    | `signer.SignXml(xml: string)` | `string` |
    | `signer.Sign(invoice: FinalizedInvoice)` | `SignedInvoice`; consumes invoice state |
    | `Xml.Hash(xml: string)` | `string` |

    `SignedInvoice` text getters: `Xml()`, `ToXmlBase64()`, `QrCode()`, `InvoiceHash()`, `HashBase64()`, `Signature()`, `PublicKey()`, `Issuer()`, `Serial()`, `CertHash()`, `SignedPropsHash()`, `SigningTime()`. Each returns `string`. `ZatcaKeySignature()` returns optional `Text`; read its `Value()` to obtain text.

    Dispose native owners, including optional `Text` and certificate `Bytes`. A `Bytes.AsSlice()` view must also be disposed; copy it with `Clone()` before releasing its owner. Native failures throw `BindingErrorException`; dispose its `Inner` after reading details.

=== "Kotlin"

    | Call | Return |
    | --- | --- |
    | `Signer.fromPem(certPem: String, keyPem: String)` | `Signer` |
    | `Signer.fromDer(certDer: ByteArray, keyDer: ByteArray)` | `Signer` |
    | `signer.certificatePem()` | `String` |
    | `signer.certificateDer()` | `Bytes` |
    | `signer.signXml(xml: String)` | `String` |
    | `signer.sign(invoice: FinalizedInvoice)` | `SignedInvoice`; consumes invoice state |
    | `Xml.hash(xml: String)` | `String` |

    `SignedInvoice` text getters: `xml()`, `toXmlBase64()`, `qrCode()`, `invoiceHash()`, `hashBase64()`, `signature()`, `publicKey()`, `issuer()`, `serial()`, `certHash()`, `signedPropsHash()`, `signingTime()`. Each returns `String`. `zatcaKeySignature()` returns optional `Text`; read its `value()` to obtain text.

    Use `use` or `close()` for native owners, including optional `Text` and certificate `Bytes`. `Bytes.asSlice()` returns a copied `ByteArray`. Failures throw `BindingException`.

=== "Java"

    | Call | Return |
    | --- | --- |
    | `Signer.fromPem(certPem: String, keyPem: String)` | `Signer` |
    | `Signer.fromDer(certDer: byte[], keyDer: byte[])` | `Signer` |
    | `signer.certificatePem()` | `String` |
    | `signer.certificateDer()` | `Bytes` |
    | `signer.signXml(xml: String)` | `String` |
    | `signer.sign(invoice: FinalizedInvoice)` | `SignedInvoice`; consumes invoice state |
    | `Xml.hash(xml: String)` | `String` |

    `SignedInvoice` text getters: `xml()`, `toXmlBase64()`, `qrCode()`, `invoiceHash()`, `hashBase64()`, `signature()`, `publicKey()`, `issuer()`, `serial()`, `certHash()`, `signedPropsHash()`, `signingTime()`. Each returns `String`. `zatcaKeySignature()` returns optional `Text`; read its `value()` to obtain text.

    Use try-with-resources for native owners, including optional `Text` and certificate `Bytes`. `Bytes.asSlice()` returns a copied `byte[]`. Failures throw `BindingException`.

=== "C"

    Include `fatoora.h`. All functions return `FatooraStatus`; inspect outputs only after `FATOORA_OK`. Inputs are borrowed for the call. Release strings with `fatoora_string_free`, bytes with `fatoora_bytes_free`, errors with `fatoora_error_free` and objects with their corresponding free function. Optional text is `NULL` when absent.

    ```c
    #include "fatoora.h"

    FatooraStatus fatoora_signer_from_pem(const char *cert_pem,
        const char *key_pem,
        FatooraSigner **out,
        FatooraError **error);

    FatooraStatus fatoora_signer_from_der(const uint8_t *cert_der,
        size_t cert_der_len,
        const uint8_t *key_der,
        size_t key_der_len,
        FatooraSigner **out,
        FatooraError **error);

    FatooraStatus fatoora_signer_certificate_pem(const FatooraSigner *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signer_certificate_der(const FatooraSigner *self,
        FatooraBytes **out,
        FatooraError **error);

    FatooraStatus fatoora_signer_sign(const FatooraSigner *self,
        FatooraFinalizedInvoice *invoice,
        FatooraSignedInvoice **out,
        FatooraError **error);

    FatooraStatus fatoora_signer_sign_xml(const FatooraSigner *self,
        const char *xml,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_xml_hash(const char *xml,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_xml(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_to_xml_base64(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_qr_code(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_invoice_hash(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_hash_base64(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_signature(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_public_key(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_zatca_key_signature(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_signed_props_hash(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_cert_hash(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_signing_time(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_issuer(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);

    FatooraStatus fatoora_signed_invoice_serial(const FatooraSignedInvoice *self,
        char **out,
        FatooraError **error);
    ```

    Signing consumes the finalized invoice state; its outer handle still needs `fatoora_finalized_invoice_free`.
