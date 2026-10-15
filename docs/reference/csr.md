---
title: ZATCA CSR and Private Key Reference
description: Reference for CSR properties, secp256k1 private keys, CSR generation, and PEM, DER, and Base64 formats, including accepted values and return types.
---

# CSR and private keys

A certificate signing request (CSR) binds a device identity to a public key. Create
properties, generate or load a private key, then build the CSR for the selected
[environment](configuration.md). For a complete runnable workflow, follow
[Generate a CSR and private key](../guides/csr.md).

## Property values

Every field is required. The constructor and properties-file parser apply the same
validation. Supply your own registered identity values for onboarding; the
[example properties file](../assets/examples/csr.properties) contains demonstration data.

| Field / properties-file key | Expected value |
| --- | --- |
| `common_name` / `csr.common.name` | Device or solution common name. |
| `serial_number` / `csr.serial.number` | Solution serial number in the format required for your device. |
| `organization_identifier` / `csr.organization.identifier` | Organization VAT identifier. |
| `organization_unit_name` / `csr.organization.unit.name` | Branch or organizational unit. |
| `organization_name` / `csr.organization.name` | Legal organization name. |
| `country_name` / `csr.country.name` | Exactly two ASCII letters, such as `SA`. |
| `invoice_type` / `csr.invoice.type` | Exactly four `0` or `1` digits, such as `1100`. |
| `location_address` / `csr.location.address` | Business location. |
| `industry_business_category` / `csr.industry.business.category` | Business activity. |

Text fields must contain non-whitespace text and cannot contain `! @ # $ % & * _ <`.
Country and invoice-type fields have the stricter formats above. Values are not
trimmed or normalized by the constructor. Country validation checks the two-letter
format, not membership in the ISO country list. Serial numbers and organization
identifiers are not checked against registration records. Passing local validation
does not guarantee that ZATCA accepts the identity.

Properties text uses `key=value` entries. Missing required keys fail; unknown keys
are ignored and repeated keys use their last value. File-loading methods read UTF-8.

## Operations and formats

| Operation | Input | Result and behavior |
| --- | --- | --- |
| Create properties | The nine fields above, in table order | Validated properties, or a validation error. |
| Parse properties | Properties text or a file path | Validated properties; fails on unreadable files, malformed text, or missing fields. |
| Generate a key | No input | A new random secp256k1 private key. |
| Load a key | PKCS#8 PEM text or DER bytes | Private key; malformed or incompatible key material fails. |
| Build a CSR | Properties, private key, environment | New CSR signed by the supplied key; properties and key remain usable. |
| Load a CSR | DER bytes | Parsed CSR; this does not establish gateway approval. |
| Read subject | CSR | Formatted distinguished-name text. |
| Read extensions | CSR | Collection of encoded extension values for inspection. |

| Output format | Contents | Typical use |
| --- | --- | --- |
| Key PEM / DER | PKCS#8 private-key material | Save or reload the signing key. |
| CSR PEM | Text with certificate-request delimiters | Save a readable `csr.pem` file. |
| CSR DER | Binary certificate request | Binary storage or parsing. |
| CSR Base64 | Base64 of DER bytes | Consumers that explicitly require encoded DER. |
| CSR PEM Base64 | Base64 of complete PEM text | ZATCA credential requests; the API client performs this conversion. |

Keep the private key: the CSR contains its public key, not the private key needed
for invoice signing. Serialization returns data and does not write files.

<span id="csrproperties"></span>
<span id="signingkey"></span>
<span id="csr"></span>
<span id="new"></span>
<span id="from_properties_str"></span>
<span id="parse_csr_config"></span>
<span id="parse_csr_config_file"></span>
<span id="build"></span>
<span id="generate"></span>
<span id="from_pem"></span>
<span id="from_der"></span>
<span id="to_pem"></span>
<span id="to_der"></span>
<span id="to_base64"></span>
<span id="to_pem_base64"></span>
<span id="subject_string"></span>
<span id="extension_values_der"></span>
<span id="errors"></span>
<span id="notes"></span>

<span id="from_der_1"></span>
<span id="to_pem_1"></span>
<span id="to_der_1"></span>
<span id="csr_1"></span>

## Language reference

Constructors that take individual fields use the order in the property table above.

=== "Rust"
    Import `CsrProperties`, `SigningKey`, and `Csr` from `fatoora_core::csr`, and
    `EnvironmentType` from `fatoora_core::config`.

    **Properties**

    ```rust
    CsrProperties::new(
        common_name: impl Into<String>, serial_number: impl Into<String>,
        organization_identifier: impl Into<String>, organization_unit_name: impl Into<String>,
        organization_name: impl Into<String>, country_name: impl Into<String>,
        invoice_type: impl Into<String>, location_address: impl Into<String>,
        industry_business_category: impl Into<String>,
    ) -> Result<CsrProperties, CsrError>
    ```

    | Call | Returns |
    | --- | --- |
    | `CsrProperties::from_properties_str(text: &str)` | `Result<CsrProperties, CsrError>` |
    | `CsrProperties::parse_csr_config(text: &str)` | Same as `from_properties_str`. |
    | `CsrProperties::parse_csr_config_file(path: impl AsRef<Path>)` | `Result<CsrProperties, CsrError>` |
    | `properties.build(key: &SigningKey, env: EnvironmentType)` | `Result<Csr, CsrError>` |

    **Private keys and CSRs**

    | Call | Returns |
    | --- | --- |
    | `SigningKey::generate()` | `SigningKey` |
    | `SigningKey::from_pem(pem: &str)` | `Result<SigningKey, CsrError>` |
    | `SigningKey::from_der(der: &[u8])` | `Result<SigningKey, CsrError>` |
    | `key.to_pem()` / `key.to_der()` | `Result<String, CsrError>` / `Result<Vec<u8>, CsrError>` |
    | `Csr::from_der(der: &[u8])` | `Result<Csr, CsrError>` |
    | `csr.to_pem()` / `csr.to_der()` | `Result<String, CsrError>` / `Result<Vec<u8>, CsrError>` |
    | `csr.to_base64()` / `csr.to_pem_base64()` | `Result<String, CsrError>` |
    | `csr.subject_string()` | `String` |
    | `csr.extension_values_der()` | `Vec<Vec<u8>>` |

    Instance methods borrow their inputs. `CsrError` distinguishes property validation,
    missing properties, file IO, parsing, key decoding, and CSR encoding/build failures.

=== "Python"
    Import `CsrProperties`, `SigningKey`, `Csr`, and `Environment` from `fatoora`.

    **Properties**

    ```python
    CsrProperties.new(
        common_name: str, serial_number: str, organization_identifier: str,
        organization_unit_name: str, organization_name: str, country_name: str,
        invoice_type: str, location_address: str, industry_business_category: str,
    ) -> CsrProperties
    ```

    | Call | Returns |
    | --- | --- |
    | `CsrProperties.from_properties_str(text: str)` | `CsrProperties` |
    | `CsrProperties.parse_csr_config(text: str)` | Alias of `from_properties_str`. |
    | `CsrProperties.parse_csr_config_file(path: str)` | `CsrProperties` |
    | `properties.build(key: SigningKey, env: Environment)` | `Csr` |
    | `SigningKey.generate()` | `SigningKey` |
    | `SigningKey.from_pem(pem: str)` / `SigningKey.from_der(der: bytes)` | `SigningKey` |
    | `key.to_pem()` / `key.to_der()` | `str` / `bytes` |
    | `Csr.from_der(der: bytes)` | `Csr` |
    | `csr.to_pem()` / `csr.to_der()` | `str` / `bytes` |
    | `csr.to_base64()` / `csr.to_pem_base64()` | `str` |
    | `csr.subject_string()` | `str` |
    | `csr.extension_values_der()` | `list[bytes]` |

    Use `Environment.NON_PRODUCTION`, `SIMULATION`, or `PRODUCTION`. Failures raise
    classified exceptions; see [Python errors](bindings/python.md). Properties, keys,
    and CSRs support `with` and `close()`. Building and serializing do not consume them.

=== "JavaScript"
    Import `CsrProperties`, `SigningKey`, and `Csr` from `fatoority`.

    **Properties**

    ```javascript
    const properties = CsrProperties.new_(
      commonName, serialNumber, organizationIdentifier, organizationUnitName,
      organizationName, countryName, invoiceType, locationAddress,
      industryBusinessCategory,
    );
    ```

    All nine arguments are strings.

    | Call | Returns |
    | --- | --- |
    | `CsrProperties.fromPropertiesStr(text)` | `CsrProperties`; `text` is a string. |
    | `properties.build(key, env)` | `Csr`; `key` is a `SigningKey`, `env` is `0`, `1`, or `2`. |
    | `SigningKey.generate()` | `SigningKey` |
    | `SigningKey.fromPem(pem)` / `SigningKey.fromDer(der)` | `SigningKey`; pass PEM string / array of byte numbers. |
    | `key.toPem()` / `key.toDer()` | String / `Bytes` |
    | `Csr.fromDer(der)` | `Csr`; pass an array of byte numbers. |
    | `csr.toPem()` / `csr.toDer()` | String / `Bytes` |
    | `csr.toBase64()` / `csr.toPemBase64()` | String |
    | `csr.subjectString()` | String |
    | `csr.extensionValuesDer()` | `BytesList` |

    These operations are synchronous and throw an `Error` with a `BindingError` cause on failure. Read files
    with your application's file APIs, then call `fromPropertiesStr`; no file-path
    constructor is exposed. Environment numbers are `0` non-production, `1` simulation,
    `2` production. Copy returned bytes with `Uint8Array.from(bytes.asSlice())` before
    retaining them across later calls. See [JavaScript resource handling](bindings/javascript.md).

=== "C#"
    Use the `Fatoora` namespace. Use `using` for returned objects, including `Bytes` and `BytesList`. Errors throw `BindingErrorException`. Use `using var view = bytes.AsSlice();` and copy bytes with `view.Clone()`. See [C# resource handling](bindings/csharp.md).

    **Properties**

    `CsrProperties.New(commonName, serialNumber, organizationIdentifier,
    organizationUnitName, organizationName, countryName, invoiceType, locationAddress,
    industryBusinessCategory)` takes nine `string` values and returns `CsrProperties`.

    | Call | Input | Returns |
    | --- | --- | --- |
    | `CsrProperties.FromPropertiesStr(text)` | `string` properties text | `CsrProperties` |
    | `CsrProperties.ParseCsrConfigFile(path)` | `string` file path | `CsrProperties` |
    | `properties.Build(key, env)` | `SigningKey`, `byte` environment | `Csr` |
    | `SigningKey.Generate()` | None | `SigningKey` |
    | `SigningKey.FromPem(pem)` | `string` PKCS#8 PEM | `SigningKey` |
    | `SigningKey.FromDer(der)` | `byte[]` PKCS#8 DER | `SigningKey` |
    | `key.ToPem()` / `key.ToDer()` | None | `string` / `Bytes` |
    | `Csr.FromDer(der)` | `byte[]` CSR DER | `Csr` |
    | `csr.ToPem()` / `csr.ToDer()` | None | `string` / `Bytes` |
    | `csr.ToBase64()` / `csr.ToPemBase64()` | None | `string` |
    | `csr.SubjectString()` | None | `string` |
    | `csr.ExtensionValuesDer()` | None | `BytesList` |

    Environment values are `0` non-production, `1` simulation, `2` production.
    Building and serializing do not consume the properties, key, or CSR.

=== "Kotlin"
    Import types from `com.fatoora`. Use `.use { ... }` or `close()` for returned objects, including `Bytes` and `BytesList`. Errors raise exceptions. Read a copied byte array with `bytes.asSlice()`. See [Kotlin resource handling](bindings/kotlin.md).

    **Properties**

    `CsrProperties.create(commonName, serialNumber, organizationIdentifier,
    organizationUnitName, organizationName, countryName, invoiceType, locationAddress,
    industryBusinessCategory)` takes nine `String` values and returns `CsrProperties`.

    | Call | Input | Returns |
    | --- | --- | --- |
    | `CsrProperties.fromPropertiesStr(text)` | `String` properties text | `CsrProperties` |
    | `CsrProperties.parseCsrConfigFile(path)` | `String` file path | `CsrProperties` |
    | `properties.build(key, env)` | `SigningKey`, `Int` environment | `Csr` |
    | `SigningKey.generate()` | None | `SigningKey` |
    | `SigningKey.fromPem(pem)` | `String` PKCS#8 PEM | `SigningKey` |
    | `SigningKey.fromDer(der)` | `ByteArray` PKCS#8 DER | `SigningKey` |
    | `key.toPem()` / `key.toDer()` | None | `String` / `Bytes` |
    | `Csr.fromDer(der)` | `ByteArray` CSR DER | `Csr` |
    | `csr.toPem()` / `csr.toDer()` | None | `String` / `Bytes` |
    | `csr.toBase64()` / `csr.toPemBase64()` | None | `String` |
    | `csr.subjectString()` | None | `String` |
    | `csr.extensionValuesDer()` | None | `BytesList` |

    Environment values are `0` non-production, `1` simulation, `2` production.
    Building and serializing do not consume the properties, key, or CSR.

=== "Java"
    Import types from `com.fatoora`. Use try-with-resources or `close()` for returned objects, including `Bytes` and `BytesList`. Errors raise exceptions. Read a copied byte array with `bytes.asSlice()`. See [Java resource handling](bindings/kotlin.md).

    **Properties**

    `CsrProperties.create(commonName, serialNumber, organizationIdentifier,
    organizationUnitName, organizationName, countryName, invoiceType, locationAddress,
    industryBusinessCategory)` takes nine `String` values and returns `CsrProperties`.

    | Call | Input | Returns |
    | --- | --- | --- |
    | `CsrProperties.fromPropertiesStr(text)` | `String` properties text | `CsrProperties` |
    | `CsrProperties.parseCsrConfigFile(path)` | `String` file path | `CsrProperties` |
    | `properties.build(key, env)` | `SigningKey`, `int` environment | `Csr` |
    | `SigningKey.generate()` | None | `SigningKey` |
    | `SigningKey.fromPem(pem)` | `String` PKCS#8 PEM | `SigningKey` |
    | `SigningKey.fromDer(der)` | `byte[]` PKCS#8 DER | `SigningKey` |
    | `key.toPem()` / `key.toDer()` | None | `String` / `Bytes` |
    | `Csr.fromDer(der)` | `byte[]` CSR DER | `Csr` |
    | `csr.toPem()` / `csr.toDer()` | None | `String` / `Bytes` |
    | `csr.toBase64()` / `csr.toPemBase64()` | None | `String` |
    | `csr.subjectString()` | None | `String` |
    | `csr.extensionValuesDer()` | None | `BytesList` |

    Environment values are `0` non-production, `1` simulation, `2` production.
    Building and serializing do not consume the properties, key, or CSR.

=== "C"
    Include `fatoora.h`. All options fields are required UTF-8 strings. Pass environment
    `0` (non-production), `1` (simulation), or `2` (production).

    **Properties and operations**

    ```c
    typedef struct FatooraCsrOptions {
        const char *common_name;
        const char *serial_number;
        const char *organization_identifier;
        const char *organization_unit_name;
        const char *organization_name;
        const char *country_name;
        const char *invoice_type;
        const char *location_address;
        const char *industry_business_category;
    } FatooraCsrOptions;

    FatooraStatus fatoora_csr_properties_new(const FatooraCsrOptions *options,
        FatooraCsrProperties **out,
        FatooraError **error);
    FatooraStatus fatoora_csr_properties_from_properties_str(const char *properties,
        FatooraCsrProperties **out,
        FatooraError **error);
    FatooraStatus fatoora_csr_properties_parse_csr_config_file(const char *path,
        FatooraCsrProperties **out,
        FatooraError **error);
    FatooraStatus fatoora_csr_properties_build(const FatooraCsrProperties *self,
        const FatooraSigningKey *key,
        int32_t env,
        FatooraCsr **out,
        FatooraError **error);
    FatooraStatus fatoora_signing_key_generate(FatooraSigningKey **out,
        FatooraError **error);
    FatooraStatus fatoora_signing_key_from_pem(const char *pem,
        FatooraSigningKey **out,
        FatooraError **error);
    FatooraStatus fatoora_signing_key_from_der(const uint8_t *der,
        size_t der_len,
        FatooraSigningKey **out,
        FatooraError **error);
    FatooraStatus fatoora_signing_key_to_pem(const FatooraSigningKey *self,
        char **out,
        FatooraError **error);
    FatooraStatus fatoora_signing_key_to_der(const FatooraSigningKey *self,
        FatooraBytes **out,
        FatooraError **error);
    FatooraStatus fatoora_csr_from_der(const uint8_t *der,
        size_t der_len,
        FatooraCsr **out,
        FatooraError **error);
    FatooraStatus fatoora_csr_to_pem(const FatooraCsr *self,
        char **out,
        FatooraError **error);
    FatooraStatus fatoora_csr_to_der(const FatooraCsr *self,
        FatooraBytes **out,
        FatooraError **error);
    FatooraStatus fatoora_csr_to_base64(const FatooraCsr *self,
        char **out,
        FatooraError **error);
    FatooraStatus fatoora_csr_to_pem_base64(const FatooraCsr *self,
        char **out,
        FatooraError **error);
    FatooraStatus fatoora_csr_subject_string(const FatooraCsr *self,
        char **out,
        FatooraError **error);
    FatooraStatus fatoora_csr_extension_values_der(const FatooraCsr *self,
        FatooraBytesList **out,
        FatooraError **error);
    ```

    Each operation returns `FatooraStatus`; `FATOORA_OK` means `out` contains the result.
    Other statuses indicate failure; inspect and release the optional `FatooraError`.
    DER input is a byte pointer plus byte count; PEM and property inputs are text.
    Inputs are borrowed for the call, and building does not consume properties or keys.

    Returned handles are owned. Release them with `fatoora_csr_properties_free`,
    `fatoora_signing_key_free`, `fatoora_csr_free`, `fatoora_bytes_free`, or
    `fatoora_bytes_list_free` as appropriate. Release returned text with
    `fatoora_string_free`. See [C errors and ownership](bindings/c.md).

## Next steps

Use the CSR with the [API client](api-client.md) to request credentials, then use
your matching private key and issued certificate for [invoice signing](invoice-signing.md).
