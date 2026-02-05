# CSR

CSR parsing and generation helpers shared by Rust, FFI, and Python.

## Csr Properties

??? note "Parse and build"
    Parse CSR properties and build a CSR.

    === "{{ lang.rust }}"
        ```rust
        CsrProperties::from_properties_str(properties: &str) -> Result<CsrProperties, CsrError>
        CsrProperties::parse_csr_config(properties: &str) -> Result<CsrProperties, CsrError>
        CsrProperties::parse_csr_config_file(path: impl AsRef<Path>) -> Result<CsrProperties, CsrError>
        CsrProperties::build(&self, signer: &SigningKey, env: EnvironmentType) -> Result<Csr, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        CsrProperties.from_properties_str(properties: str) -> CsrProperties
        CsrProperties.parse(properties: str) -> CsrProperties
        CsrProperties.parse_file(path: str) -> CsrProperties
        CsrProperties.build(key: SigningKey, env: Environment) -> Csr
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsrProperties fatoora_csr_properties_from_str(const char* properties);
        FfiResult_FfiCsrProperties fatoora_csr_properties_parse(const char* properties);
        FfiResult_FfiCsrProperties fatoora_csr_properties_parse_file(const char* path);
        FfiResult_FfiCsr fatoora_csr_build(FfiCsrProperties* props, FfiSigningKey* key, FfiEnvironment env);
        ```

    !!! info "Args"
        - `properties`: CSR properties text.
        - `path`: file path for properties.
        - `signer` / `key`: signing key.
        - `env`: environment used to select template name.

    !!! info "Returns"
        - `CsrProperties`: parsed properties.
        - `Csr`: CSR object built from properties.

## Signing Key

??? note "Key generation and IO"
    Create and serialize signing keys.

    === "{{ lang.rust }}"
        ```rust
        SigningKey::generate() -> SigningKey
        SigningKey::from_pem(pem: &str) -> Result<SigningKey, CsrError>
        SigningKey::from_der(der: &[u8]) -> Result<SigningKey, CsrError>
        SigningKey::to_pem(&self) -> Result<String, CsrError>
        SigningKey::to_der(&self) -> Result<Vec<u8>, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        SigningKey.generate() -> SigningKey
        SigningKey.from_pem(pem: str) -> SigningKey
        SigningKey.from_der(der: bytes) -> SigningKey
        SigningKey.to_pem() -> str
        SigningKey.to_der() -> bytes
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiSigningKey fatoora_signing_key_generate(void);
        FfiResult_FfiSigningKey fatoora_signing_key_from_pem(const char* pem);
        FfiResult_FfiSigningKey fatoora_signing_key_from_der(const uint8_t* der, uintptr_t len);
        FfiResult_FfiString fatoora_signing_key_to_pem(FfiSigningKey* key);
        FfiResult_FfiBytes fatoora_signing_key_to_der(FfiSigningKey* key);
        ```

    !!! info "Args"
        - `pem` / `der`: PKCS#8 key material.

    !!! info "Returns"
        - `SigningKey`: signing key handle.
        - `pem` / `der`: serialized key output.

## CSR

??? note "CSR IO"
    Load and serialize CSR data.

    === "{{ lang.rust }}"
        ```rust
        Csr::from_der(der: &[u8]) -> Result<Csr, CsrError>
        Csr::to_pem(&self) -> Result<String, CsrError>
        Csr::to_der(&self) -> Result<Vec<u8>, CsrError>
        Csr::to_base64(&self) -> Result<String, CsrError>
        Csr::to_pem_base64(&self) -> Result<String, CsrError>
        Csr::subject_string(&self) -> String
        Csr::extension_values_der(&self) -> Vec<Vec<u8>>
        ```

    === "{{ lang.python }}"
        ```python
        Csr.from_der(der: bytes) -> Csr
        Csr.to_pem() -> str
        Csr.to_der() -> bytes
        Csr.to_base64() -> str
        Csr.to_pem_base64() -> str
        Csr.subject_string() -> str
        Csr.extension_values_der() -> list[bytes]
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsr fatoora_csr_from_der(const uint8_t* der, uintptr_t len);
        FfiResult_FfiString fatoora_csr_to_pem(FfiCsr* csr);
        FfiResult_FfiBytes fatoora_csr_to_der(FfiCsr* csr);
        FfiResult_FfiString fatoora_csr_to_base64(FfiCsr* csr);
        FfiResult_FfiString fatoora_csr_to_pem_base64(FfiCsr* csr);
        FfiResult_FfiString fatoora_csr_subject_string(FfiCsr* csr);
        FfiResult_FfiBytesList fatoora_csr_extension_values_der(FfiCsr* csr);
        ```

    !!! info "Args"
        - `der`: CSR in DER format.

    !!! info "Returns"
        - `Csr`: CSR object.
        - `pem` / `der` / `base64`: serialized CSR output.

## Errors

!!! warning "Errors"
    - `CsrError` covers parsing, missing fields, subject/SAN build failures, encoding issues, and IO.

!!! note "Notes"
    - The template name extension is selected from EnvironmentType.
    - Csr.to_pem_base64() is the value expected by the ZATCA compliance endpoint.

See also: [CSR Guide](../guides/csr.md)
