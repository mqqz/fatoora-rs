# CSR

See [C and C++ bindings](bindings/c.md) for ownership rules and text output.
The declarations below come from the generated headers. C++ exposes the same types
in namespace `fatoora` through `fatoora/Type.hpp` headers.

CSR parsing and generation helpers shared by Rust, FFI, and Python.

## CsrProperties

### `new`

???+ note "Create CSR properties"
    Construct `CsrProperties` from explicit fields.

    === "{{ lang.rust }}"
        ```rust
        CsrProperties::new(
            common_name: impl Into<String>,
            serial_number: impl Into<String>,
            organization_identifier: impl Into<String>,
            organization_unit_name: impl Into<String>,
            organization_name: impl Into<String>,
            country_name: impl Into<String>,
            invoice_type: impl Into<String>,
            location_address: impl Into<String>,
            industry_business_category: impl Into<String>,
        ) -> Result<CsrProperties, CsrError>
        ```

    === "{{ lang.python }}"
        ```python
        CsrProperties.new(
            common_name: str,
            serial_number: str,
            organization_identifier: str,
            organization_unit_name: str,
            organization_name: str,
            country_name: str,
            invoice_type: str,
            location_address: str,
            industry_business_category: str,
        ) -> CsrProperties
        ```

    === "{{ lang.c }}"
        ```c
        #include "CsrProperties.h"

        fatoora_CsrProperties_new_result fatoora_CsrProperties_new(DiplomatStringView common_name, DiplomatStringView serial_number, DiplomatStringView organization_identifier, DiplomatStringView organization_unit_name, DiplomatStringView organization_name, DiplomatStringView country_name, DiplomatStringView invoice_type, DiplomatStringView location_address, DiplomatStringView industry_business_category);
        ```

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
        #include "CsrProperties.h"

        fatoora_CsrProperties_from_properties_str_result fatoora_CsrProperties_from_properties_str(DiplomatStringView properties);
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
        #include "CsrProperties.h"

        fatoora_CsrProperties_from_properties_str_result fatoora_CsrProperties_from_properties_str(DiplomatStringView properties);
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
        #include "CsrProperties.h"

        fatoora_CsrProperties_parse_csr_config_file_result fatoora_CsrProperties_parse_csr_config_file(DiplomatStringView path);
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
        #include "CsrProperties.h"

        fatoora_CsrProperties_build_result fatoora_CsrProperties_build(const CsrProperties* self, const SigningKey* key, uint8_t env);
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
        #include "SigningKey.h"

        fatoora_SigningKey_generate_result fatoora_SigningKey_generate(void);
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
        #include "SigningKey.h"

        fatoora_SigningKey_from_pem_result fatoora_SigningKey_from_pem(DiplomatStringView pem);
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
        #include "SigningKey.h"

        fatoora_SigningKey_from_der_result fatoora_SigningKey_from_der(DiplomatU8View der);
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
        #include "SigningKey.h"

        fatoora_SigningKey_to_pem_result fatoora_SigningKey_to_pem(const SigningKey* self, DiplomatWrite* write);
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
        #include "SigningKey.h"

        fatoora_SigningKey_to_der_result fatoora_SigningKey_to_der(const SigningKey* self);
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
        #include "Csr.h"

        fatoora_Csr_from_der_result fatoora_Csr_from_der(DiplomatU8View der);
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
        #include "Csr.h"

        fatoora_Csr_to_pem_result fatoora_Csr_to_pem(const Csr* self, DiplomatWrite* write);
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
        #include "Csr.h"

        fatoora_Csr_to_der_result fatoora_Csr_to_der(const Csr* self);
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
        #include "Csr.h"

        fatoora_Csr_to_base64_result fatoora_Csr_to_base64(const Csr* self, DiplomatWrite* write);
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
        #include "Csr.h"

        fatoora_Csr_to_pem_base64_result fatoora_Csr_to_pem_base64(const Csr* self, DiplomatWrite* write);
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
        #include "Csr.h"

        fatoora_Csr_subject_string_result fatoora_Csr_subject_string(const Csr* self, DiplomatWrite* write);
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
        #include "Csr.h"

        fatoora_Csr_extension_values_der_result fatoora_Csr_extension_values_der(const Csr* self);
        ```

## Errors

!!! warning "Errors"
    - `CsrError` covers parsing, missing fields, subject/SAN build failures, encoding issues, and IO.

## Notes

!!! note "Notes"
    - The template name extension is selected from `EnvironmentType`.
    - `Csr.to_pem_base64()` is the value expected by the ZATCA compliance endpoint.

See also: [CSR Guide](../guides/csr.md)
