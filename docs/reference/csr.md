# CSR

CSR parsing and generation helpers shared by Rust, FFI, and Python.

## CsrProperties

### from_properties_str

??? note "Parse CSR properties string"
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

    !!! info "Args"
        - `properties` (`&str` / `str` / `const char*`): CSR properties text.

    !!! info "Returns"
        - Rust: `Result<CsrProperties, CsrError>`.
        - Python: `CsrProperties`.
        - C: `FfiResult_FfiCsrProperties`.

### parse_csr_config / parse

??? note "Parse CSR config"
    Parse properties text using the config parser alias.

    === "{{ lang.rust }}"
        ```rust
        CsrProperties::parse_csr_config(properties: &str) -> Result<CsrProperties, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        CsrProperties.parse(properties: str) -> CsrProperties
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsrProperties fatoora_csr_properties_parse(const char* properties);
        ```

    !!! info "Args"
        - `properties` (`&str` / `str` / `const char*`): CSR properties text.

    !!! info "Returns"
        - Rust: `Result<CsrProperties, CsrError>`.
        - Python: `CsrProperties`.
        - C: `FfiResult_FfiCsrProperties`.

### parse_csr_config_file / parse_file

??? note "Parse CSR config file"
    Parse properties from a file path.

    === "{{ lang.rust }}"
        ```rust
        CsrProperties::parse_csr_config_file(path: impl AsRef<Path>) -> Result<CsrProperties, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        CsrProperties.parse_file(path: str) -> CsrProperties
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsrProperties fatoora_csr_properties_parse_file(const char* path);
        ```

    !!! info "Args"
        - `path` (`impl AsRef<Path>` / `str` / `const char*`): properties file path.

    !!! info "Returns"
        - Rust: `Result<CsrProperties, CsrError>`.
        - Python: `CsrProperties`.
        - C: `FfiResult_FfiCsrProperties`.

### build

??? note "Build CSR"
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

    !!! info "Args"
        - `signer` / `key` (`&SigningKey` / `SigningKey` / `FfiSigningKey*`): signing key.
        - `env` (`EnvironmentType` / `Environment` / `FfiEnvironment`): template environment.

    !!! info "Returns"
        - Rust: `Result<Csr, CsrError>`.
        - Python: `Csr`.
        - C: `FfiResult_FfiCsr`.

## SigningKey

### generate

??? note "Generate key"
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

    !!! info "Returns"
        - Rust: `SigningKey`.
        - Python: `SigningKey`.
        - C: `FfiResult_FfiSigningKey`.

### from_pem

??? note "Load key from PEM"
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

    !!! info "Args"
        - `pem` (`&str` / `str` / `const char*`): PEM key material.

    !!! info "Returns"
        - Rust: `Result<SigningKey, CsrError>`.
        - Python: `SigningKey`.
        - C: `FfiResult_FfiSigningKey`.

### from_der

??? note "Load key from DER"
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

    !!! info "Args"
        - `der` (`&[u8]` / `bytes` / `const uint8_t*` + `len`): DER key bytes.

    !!! info "Returns"
        - Rust: `Result<SigningKey, CsrError>`.
        - Python: `SigningKey`.
        - C: `FfiResult_FfiSigningKey`.

### to_pem

??? note "Serialize key to PEM"
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

    !!! info "Returns"
        - Rust: `Result<String, CsrError>`.
        - Python: `str`.
        - C: `FfiResult_FfiString`.

### to_der

??? note "Serialize key to DER"
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

    !!! info "Returns"
        - Rust: `Result<Vec<u8>, CsrError>`.
        - Python: `bytes`.
        - C: `FfiResult_FfiBytes`.

## Csr

### from_der

??? note "Load CSR from DER"
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

    !!! info "Args"
        - `der` (`&[u8]` / `bytes` / `const uint8_t*` + `len`): DER CSR bytes.

    !!! info "Returns"
        - Rust: `Result<Csr, CsrError>`.
        - Python: `Csr`.
        - C: `FfiResult_FfiCsr`.

### to_pem

??? note "Serialize CSR to PEM"

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

    !!! info "Returns"
        - Rust: `Result<String, CsrError>`.
        - Python: `str`.
        - C: `FfiResult_FfiString`.

### to_der

??? note "Serialize CSR to DER"

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

    !!! info "Returns"
        - Rust: `Result<Vec<u8>, CsrError>`.
        - Python: `bytes`.
        - C: `FfiResult_FfiBytes`.

### to_base64

??? note "Serialize CSR DER to Base64"

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

    !!! info "Returns"
        - Rust: `Result<String, CsrError>`.
        - Python: `str`.
        - C: `FfiResult_FfiString`.

### to_pem_base64

??? note "Serialize PEM CSR to Base64"

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

    !!! info "Returns"
        - Rust: `Result<String, CsrError>`.
        - Python: `str`.
        - C: `FfiResult_FfiString`.

### subject_string

??? note "Get CSR subject string"

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

    !!! info "Returns"
        - Rust: `String`.
        - Python: `str`.
        - C: `FfiResult_FfiString`.

### extension_values_der

??? note "Get extension DER values"

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

    !!! info "Returns"
        - Rust: `Vec<Vec<u8>>`.
        - Python: `list[bytes]`.
        - C: `FfiResult_FfiBytesList`.

## Errors

!!! warning "Errors"
    - `CsrError` covers parsing, missing fields, subject/SAN build failures, encoding issues, and IO.

## Notes

!!! note "Notes"
    - The template name extension is selected from `EnvironmentType`.
    - `Csr.to_pem_base64()` is the value expected by the ZATCA compliance endpoint.

See also: [CSR Guide](../guides/csr.md)
