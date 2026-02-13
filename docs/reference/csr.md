# CSR

CSR parsing and generation helpers shared by Rust, FFI, and Python.

## CsrProperties

### `from_properties_str`

???+ note "Parse CSR properties string"
    Parse properties text into `CsrProperties`.

    === "{{ lang.rust }}"
        ```rust
        CsrProperties::from_properties_str(properties: &str) -> Result<CsrProperties, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        CsrProperties.from_properties_str(properties: str) -> CsrProperties
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsrProperties fatoora_csr_properties_from_str(const char* properties);
        ```

### `parse_csr_config`

???+ note "Parse CSR config"
    Parse properties text using the config parser alias.

    === "{{ lang.rust }}"
        ```rust
        CsrProperties::parse_csr_config(properties: &str) -> Result<CsrProperties, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        CsrProperties.parse_csr_config(properties: str) -> CsrProperties
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsrProperties fatoora_csr_properties_parse_csr_config(const char* properties);
        ```

### `parse_csr_config_file`

???+ note "Parse CSR config file"
    Parse properties from a file path.

    === "{{ lang.rust }}"
        ```rust
        CsrProperties::parse_csr_config_file(path: impl AsRef<Path>) -> Result<CsrProperties, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        CsrProperties.parse_csr_config_file(path: str) -> CsrProperties
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsrProperties fatoora_csr_properties_parse_csr_config_file(const char* path);
        ```

### `build`

???+ note "Build CSR"
    Build a CSR from properties and signing key.

    === "{{ lang.rust }}"
        ```rust
        CsrProperties::build(&self, signer: &SigningKey, env: EnvironmentType) -> Result<Csr, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        CsrProperties.build(key: SigningKey, env: Environment) -> Csr
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsr fatoora_csr_build(FfiCsrProperties* props, FfiSigningKey* key, FfiEnvironment env);
        ```

## SigningKey

### `generate`

???+ note "Generate key"
    Generate a new signing key.

    === "{{ lang.rust }}"
        ```rust
        SigningKey::generate() -> SigningKey
        ```

    === "{{ lang.python }}"
        ```python
        SigningKey.generate() -> SigningKey
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiSigningKey fatoora_signing_key_generate(void);
        ```

### `from_pem`

???+ note "Load key from PEM"
    Parse PKCS#8 key material in PEM format.

    === "{{ lang.rust }}"
        ```rust
        SigningKey::from_pem(pem: &str) -> Result<SigningKey, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        SigningKey.from_pem(pem: str) -> SigningKey
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiSigningKey fatoora_signing_key_from_pem(const char* pem);
        ```

### `from_der`

???+ note "Load key from DER"
    Parse PKCS#8 key material in DER format.

    === "{{ lang.rust }}"
        ```rust
        SigningKey::from_der(der: &[u8]) -> Result<SigningKey, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        SigningKey.from_der(der: bytes) -> SigningKey
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiSigningKey fatoora_signing_key_from_der(const uint8_t* der, uintptr_t len);
        ```

### `to_pem`

???+ note "Serialize key to PEM"
    Serialize the key to PEM format.

    === "{{ lang.rust }}"
        ```rust
        SigningKey::to_pem(&self) -> Result<String, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        SigningKey.to_pem() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_signing_key_to_pem(FfiSigningKey* key);
        ```

### `to_der`

???+ note "Serialize key to DER"
    Serialize the key to DER format.

    === "{{ lang.rust }}"
        ```rust
        SigningKey::to_der(&self) -> Result<Vec<u8>, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        SigningKey.to_der() -> bytes
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiBytes fatoora_signing_key_to_der(FfiSigningKey* key);
        ```

## Csr

### `from_der`

???+ note "Load CSR from DER"
    Parse CSR bytes in DER format.

    === "{{ lang.rust }}"
        ```rust
        Csr::from_der(der: &[u8]) -> Result<Csr, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        Csr.from_der(der: bytes) -> Csr
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsr fatoora_csr_from_der(const uint8_t* der, uintptr_t len);
        ```

### `to_pem`

???+ note "Serialize CSR to PEM"

    === "{{ lang.rust }}"
        ```rust
        Csr::to_pem(&self) -> Result<String, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        Csr.to_pem() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_csr_to_pem(FfiCsr* csr);
        ```

### `to_der`

???+ note "Serialize CSR to DER"

    === "{{ lang.rust }}"
        ```rust
        Csr::to_der(&self) -> Result<Vec<u8>, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        Csr.to_der() -> bytes
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiBytes fatoora_csr_to_der(FfiCsr* csr);
        ```

### `to_base64`

???+ note "Serialize CSR DER to Base64"

    === "{{ lang.rust }}"
        ```rust
        Csr::to_base64(&self) -> Result<String, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        Csr.to_base64() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_csr_to_base64(FfiCsr* csr);
        ```

### `to_pem_base64`

???+ note "Serialize PEM CSR to Base64"

    === "{{ lang.rust }}"
        ```rust
        Csr::to_pem_base64(&self) -> Result<String, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        Csr.to_pem_base64() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_csr_to_pem_base64(FfiCsr* csr);
        ```

### `subject_string`

???+ note "Get CSR subject string"

    === "{{ lang.rust }}"
        ```rust
        Csr::subject_string(&self) -> String
        ```

    === "{{ lang.python }}"
        ```python
        Csr.subject_string() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_csr_subject_string(FfiCsr* csr);
        ```

### `extension_values_der`

???+ note "Get extension DER values"

    === "{{ lang.rust }}"
        ```rust
        Csr::extension_values_der(&self) -> Vec<Vec<u8>>
        ```

    === "{{ lang.python }}"
        ```python
        Csr.extension_values_der() -> list[bytes]
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiBytesList fatoora_csr_extension_values_der(FfiCsr* csr);
        ```

## Errors

!!! warning "Errors"
    - `CsrError` covers parsing, missing fields, subject/SAN build failures, encoding issues, and IO.

## Notes

!!! note "Notes"
    - The template name extension is selected from `EnvironmentType`.
    - `Csr.to_pem_base64()` is the value expected by the ZATCA compliance endpoint.

See also: [CSR Guide](../guides/csr.md)
