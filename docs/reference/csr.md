# CSR

CSR parsing and generation helpers shared by Rust, FFI, and Python.

## Symbols

=== "Rust"
    - `CsrProperties::from_properties_str(properties: &str) -> Result<CsrProperties, CsrError>` — parse CSR properties from a string.
    - `CsrProperties::parse_csr_config(properties: &str) -> Result<CsrProperties, CsrError>` — alias for `from_properties_str`.
    - `CsrProperties::parse_csr_config_file(path: impl AsRef<Path>) -> Result<CsrProperties, CsrError>` — parse properties file.
    - `CsrProperties::build(&self, signer: &SigningKey, env: EnvironmentType) -> Result<Csr, CsrError>` — build CSR.
    - `SigningKey::generate() -> SigningKey` — generate a new K256 signing key.
    - `SigningKey::from_pem(pem: &str) -> Result<SigningKey, CsrError>` — parse PKCS#8 PEM key.
    - `SigningKey::from_der(der: &[u8]) -> Result<SigningKey, CsrError>` — parse PKCS#8 DER key.
    - `SigningKey::to_pem(&self) -> Result<String, CsrError>` — serialize to PEM.
    - `SigningKey::to_der(&self) -> Result<Vec<u8>, CsrError>` — serialize to DER.
    - `Csr::from_der(der: &[u8]) -> Result<Csr, CsrError>` — load CSR from DER.
    - `Csr::to_pem(&self) -> Result<String, CsrError>` — serialize CSR to PEM.
    - `Csr::to_der(&self) -> Result<Vec<u8>, CsrError>` — serialize CSR to DER.
    - `Csr::to_base64(&self) -> Result<String, CsrError>` — base64 of DER.
    - `Csr::to_pem_base64(&self) -> Result<String, CsrError>` — base64 of PEM.
    - `Csr::subject_string(&self) -> String` — subject DN string.
    - `Csr::extension_values_der(&self) -> Vec<Vec<u8>>` — raw DER values of extensions.

=== "Python"
    - `CsrProperties.from_properties_str(properties: str) -> CsrProperties`
    - `CsrProperties.parse(properties: str) -> CsrProperties`
    - `CsrProperties.parse_file(path: str) -> CsrProperties`
    - `CsrProperties.build(key: SigningKey, env: Environment) -> Csr`
    - `SigningKey.generate() -> SigningKey`
    - `SigningKey.from_pem(pem: str) -> SigningKey`
    - `SigningKey.from_der(der: bytes) -> SigningKey`
    - `SigningKey.to_pem() -> str`
    - `SigningKey.to_der() -> bytes`
    - `Csr.from_der(der: bytes) -> Csr`
    - `Csr.to_pem() -> str`
    - `Csr.to_der() -> bytes`
    - `Csr.to_base64() -> str`
    - `Csr.to_pem_base64() -> str`
    - `Csr.subject_string() -> str`
    - `Csr.extension_values_der() -> list[bytes]`

=== "C (FFI)"
    - `fatoora_csr_properties_from_str(properties: const char*) -> FfiResult_FfiCsrProperties`
    - `fatoora_csr_properties_parse(properties: const char*) -> FfiResult_FfiCsrProperties`
    - `fatoora_csr_properties_parse_file(path: const char*) -> FfiResult_FfiCsrProperties`
    - `fatoora_csr_build(props: FfiCsrProperties*, key: FfiSigningKey*, env: FfiEnvironment) -> FfiResult_FfiCsr`
    - `fatoora_signing_key_generate() -> FfiResult_FfiSigningKey`
    - `fatoora_signing_key_from_pem(pem: const char*) -> FfiResult_FfiSigningKey`
    - `fatoora_signing_key_from_der(der: const uint8_t*, len: uintptr_t) -> FfiResult_FfiSigningKey`
    - `fatoora_signing_key_to_pem(key: FfiSigningKey*) -> FfiResult_FfiString`
    - `fatoora_signing_key_to_der(key: FfiSigningKey*) -> FfiResult_FfiBytes`
    - `fatoora_csr_from_der(der: const uint8_t*, len: uintptr_t) -> FfiResult_FfiCsr`
    - `fatoora_csr_to_pem(csr: FfiCsr*) -> FfiResult_FfiString`
    - `fatoora_csr_to_der(csr: FfiCsr*) -> FfiResult_FfiBytes`
    - `fatoora_csr_to_base64(csr: FfiCsr*) -> FfiResult_FfiString`
    - `fatoora_csr_to_pem_base64(csr: FfiCsr*) -> FfiResult_FfiString`
    - `fatoora_csr_subject_string(csr: FfiCsr*) -> FfiResult_FfiString`
    - `fatoora_csr_extension_values_der(csr: FfiCsr*) -> FfiResult_FfiBytesList`

## Types
- `CsrProperties` validates fields, builds the subject/SAN, and constructs the request.
- `SigningKey` wraps the K256 private key and controls PEM/DER I/O.
- `Csr` wraps the generated request and supports base64 and PEM/DER output.
- `CsrError` covers parsing, missing fields, subject/SAN build failures, encoding issues, and IO.

## Notes
- The template name extension is selected from `EnvironmentType`.
- `Csr::to_pem_base64()` is the value expected by the ZATCA compliance endpoint.

See also: [CSR Guide](../guides/csr.md)
