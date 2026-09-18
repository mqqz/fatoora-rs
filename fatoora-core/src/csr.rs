//! CSR generation and helpers.
use crate::config::EnvironmentType;
use base64ct::{Base64, Encoding};
use ecdsa;
use fatoora_derive::Validate;
use java_properties::PropertiesIter;
use k256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding as KeyLineEnding};
use k256::{Secp256k1, ecdsa::SigningKey as K256SigningKey};
use std::{
    io::Cursor,
    path::{self, PathBuf},
    str::FromStr,
    vec,
};
use thiserror::Error;
use x509_cert::{
    builder::{Builder, RequestBuilder},
    der::{
        Decode, Encode, EncodePem, Length, Result as DerResult, Writer,
        pem::LineEnding as CsrLineEnding,
    },
    ext::{
        AsExtension, Extension,
        pkix::{SubjectAltName, name::GeneralName},
    },
    name,
    request::CertReq,
};

/// Errors that can occur while generating or validating CSRs.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CsrError {
    #[error("failed to open CSR config file '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse CSR properties from '{path}': {source}")]
    PropertiesRead {
        path: PathBuf,
        #[source]
        source: crate::Diagnostic,
    },

    #[error("missing required CSR property '{key}' in file '{path}'")]
    MissingProperty { path: PathBuf, key: String },

    #[error("invalid subject distinguished name constructed from provided fields: {message}")]
    InvalidSubject { message: String },

    #[error("invalid Subject Alternative Name (SAN) from fields: {message}")]
    InvalidSan { message: String },

    #[error("failed to construct CSR request: {message}")]
    RequestBuild { message: String },

    #[error("failed adding CSR extension '{which}': {message}")]
    AddExtension {
        which: &'static str,
        message: String,
    },

    #[error("failed to build CSR: {message}")]
    CsrBuild { message: String },

    #[error("failed to decode signing key: {message}")]
    KeyDecode { message: String },

    #[error("failed to encode signing key: {message}")]
    KeyEncode { message: String },

    #[error("failed DER encoding for {context}: {source}")]
    DerEncode {
        context: &'static str,
        #[source]
        source: crate::Diagnostic,
    },

    #[error("validation error: {message}")]
    Validation { message: String },
}

impl CsrError {
    /// Shared classification used by bindings.
    pub fn kind(&self) -> crate::ErrorKind {
        match self {
            Self::Io { .. } => crate::ErrorKind::Io,
            Self::PropertiesRead { .. } => crate::ErrorKind::Parse,
            Self::MissingProperty { .. } => crate::ErrorKind::InvalidInput,
            Self::InvalidSubject { .. } => crate::ErrorKind::InvalidInput,
            Self::InvalidSan { .. } => crate::ErrorKind::InvalidInput,
            Self::RequestBuild { .. } => crate::ErrorKind::Crypto,
            Self::AddExtension { .. } => crate::ErrorKind::Crypto,
            Self::CsrBuild { .. } => crate::ErrorKind::Crypto,
            Self::DerEncode { .. } => crate::ErrorKind::Crypto,
            Self::KeyDecode { .. } => crate::ErrorKind::InvalidInput,
            Self::KeyEncode { .. } => crate::ErrorKind::Crypto,
            Self::Validation { .. } => crate::ErrorKind::Validation,
        }
    }
}

struct TemplateNameExtension(pub String);

impl const_oid::AssociatedOid for TemplateNameExtension {
    const OID: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.20.2");
}

impl Encode for TemplateNameExtension {
    fn encoded_len(&self) -> DerResult<Length> {
        self.0.encoded_len()
    }
    fn encode(&self, encoder: &mut impl Writer) -> DerResult<()> {
        self.0.encode(encoder)
    }
}

impl AsExtension for TemplateNameExtension {
    fn critical(&self, _name: &name::Name, _exts: &[Extension]) -> bool {
        false
    }
}

impl EnvironmentType {
    const fn as_template_bytes(&self) -> &'static [u8] {
        match self {
            EnvironmentType::NonProduction => b"TSTZATCA-Code-Signing",
            EnvironmentType::Simulation => b"PREZATCA-Code-Signing",
            EnvironmentType::Production => b"ZATCA-Code-Signing",
        }
    }

    fn to_extension(self) -> Result<TemplateNameExtension, CsrError> {
        let bytes = self.as_template_bytes();
        // The SDK encodes the template's inner value as ASN.1 UTF8String.
        // Extension itself supplies the surrounding OCTET STRING.
        Ok(TemplateNameExtension(
            String::from_utf8(bytes.to_vec()).expect("ASCII template name"),
        ))
    }
}

/// Wrapper for CSR signing keys.
#[derive(Debug, Clone)]
pub struct SigningKey {
    inner: K256SigningKey,
}

impl SigningKey {
    pub fn generate() -> Self {
        Self {
            inner: ecdsa::SigningKey::<Secp256k1>::generate(),
        }
    }

    pub fn from_der(der: &[u8]) -> Result<Self, CsrError> {
        let inner = K256SigningKey::from_pkcs8_der(der).map_err(|e| CsrError::KeyDecode {
            message: e.to_string(),
        })?;
        Ok(Self { inner })
    }

    pub fn from_pem(pem: &str) -> Result<Self, CsrError> {
        let inner = K256SigningKey::from_pkcs8_pem(pem).map_err(|e| CsrError::KeyDecode {
            message: e.to_string(),
        })?;
        Ok(Self { inner })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, CsrError> {
        let doc =
            self.inner
                .to_pkcs8_der()
                .map_err(|e: k256::pkcs8::Error| CsrError::KeyEncode {
                    message: e.to_string(),
                })?;
        Ok(doc.as_bytes().to_vec())
    }

    pub fn to_pem(&self) -> Result<String, CsrError> {
        let pem = self
            .inner
            .to_pkcs8_pem(KeyLineEnding::LF)
            .map_err(|e: k256::pkcs8::Error| CsrError::KeyEncode {
                message: e.to_string(),
            })?;
        Ok(pem.to_string())
    }

    pub(crate) fn inner(&self) -> &K256SigningKey {
        &self.inner
    }
}

/// Wrapper for certificate signing requests.
#[derive(Debug, Clone)]
pub struct Csr {
    inner: CertReq,
}

impl Csr {
    pub fn from_der(der: &[u8]) -> Result<Self, CsrError> {
        let inner = CertReq::from_der(der).map_err(|e| CsrError::DerEncode {
            context: "certificate request (DER)",
            source: crate::Diagnostic::new(e.to_string()),
        })?;
        Ok(Self { inner })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, CsrError> {
        let der_bytes = self.inner.to_der().map_err(|e| CsrError::DerEncode {
            context: "certificate request",
            source: crate::Diagnostic::new(e.to_string()),
        })?;
        Ok(der_bytes)
    }

    pub fn to_pem(&self) -> Result<String, CsrError> {
        let pem = self
            .inner
            .to_pem(CsrLineEnding::LF)
            .map_err(|e| CsrError::DerEncode {
                context: "certificate request (PEM)",
                source: crate::Diagnostic::new(e.to_string()),
            })?;
        Ok(pem)
    }

    pub fn to_base64(&self) -> Result<String, CsrError> {
        let der_bytes = self.to_der()?;
        Ok(Base64::encode_string(&der_bytes))
    }

    pub fn to_pem_base64(&self) -> Result<String, CsrError> {
        let pem = self.to_pem()?;
        Ok(Base64::encode_string(pem.as_bytes()))
    }

    pub fn subject_string(&self) -> String {
        self.inner.info.subject.to_string()
    }

    pub fn extension_values_der(&self) -> Vec<Vec<u8>> {
        self.inner
            .info
            .attributes
            .iter()
            .flat_map(|attr| attr.values.iter())
            .filter_map(|value| value.to_der().ok())
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &CertReq {
        &self.inner
    }
}

/// CSR properties parsed from the SDK properties file.
///
/// # Examples
/// ```rust,no_run
/// use fatoora_core::config::EnvironmentType;
/// use fatoora_core::csr::CsrProperties;
///
/// let props = CsrProperties::from_properties_str("csr.common.name=example")?;
/// let key = fatoora_core::csr::SigningKey::generate();
/// let csr = props.build(&key, EnvironmentType::NonProduction)?;
/// # let _ = csr;
/// use fatoora_core::csr::CsrError;
/// # Ok::<(), CsrError>(())
/// ```
#[allow(dead_code)]
#[derive(Validate, Debug, Clone, PartialEq, Eq, Hash)]
#[validate_error(CsrError)]
#[validate(non_empty, no_special_chars)]
pub struct CsrProperties {
    common_name: String,
    serial_number: String,
    organization_identifier: String,
    organization_unit_name: String,
    organization_name: String,
    #[validate(is_country_code)]
    country_name: String,
    #[validate(non_empty, no_special_chars, four_binary_digits)]
    invoice_type: String,
    location_address: String,
    industry_business_category: String,
}

impl CsrProperties {
    fn generate_subject(&self) -> Result<name::Name, CsrError> {
        name::Name::from_str(&format!(
            "CN={},O={},OU={},C={}",
            &self.common_name,
            &self.organization_name,
            &self.organization_unit_name,
            &self.country_name
        ))
        .map_err(|e| CsrError::InvalidSubject {
            message: e.to_string(),
        })
    }

    fn generate_template_name_extension(
        &self,
        env: EnvironmentType,
    ) -> Result<TemplateNameExtension, CsrError> {
        env.to_extension()
    }

    fn generate_san_extension(&self) -> Result<SubjectAltName, CsrError> {
        let name = name::Name::from_str(&format!(
            "businessCategory={},registeredAddress={},title={},uid={},sn={}",
            &self.industry_business_category,
            &self.location_address,
            &self.invoice_type,
            &self.organization_identifier,
            &self.serial_number
        ))
        .map_err(|e| CsrError::InvalidSan {
            message: e.to_string(),
        })?;
        let dir_name = GeneralName::DirectoryName(name);
        Ok(SubjectAltName::from(vec![dir_name]))
    }

    /// Build a CSR using the provided signer.
    ///
    /// # Errors
    /// Returns [`CsrError`] when subject or extension generation fails.
    pub fn build(&self, signer: &SigningKey, env: EnvironmentType) -> Result<Csr, CsrError> {
        let subject = self.generate_subject()?;
        let asn1_extension = self.generate_template_name_extension(env)?;
        let san_extension = self.generate_san_extension()?;

        let mut csr_builder = RequestBuilder::new(subject).map_err(|e| CsrError::RequestBuild {
            message: e.to_string(),
        })?;
        csr_builder
            .add_extension(&asn1_extension)
            .map_err(|e| CsrError::AddExtension {
                which: "TemplateName",
                message: e.to_string(),
            })?;
        csr_builder
            .add_extension(&san_extension)
            .map_err(|e| CsrError::AddExtension {
                which: "SubjectAltName",
                message: e.to_string(),
            })?;
        csr_builder
            .build::<_, ecdsa::der::Signature<_>>(signer.inner())
            .map_err(|e| CsrError::CsrBuild {
                message: e.to_string(),
            })
            .map(|inner| Csr { inner })
    }

    /// Parse a CSR properties string.
    ///
    /// # Errors
    /// Returns [`CsrError`] when the properties cannot be read or required fields are missing.
    pub fn from_properties_str(properties: &str) -> Result<CsrProperties, CsrError> {
        let pathbuf = path::PathBuf::from("<properties>");
        let cursor = Cursor::new(properties.as_bytes());
        let mut dst_map = std::collections::HashMap::new();
        PropertiesIter::new_with_encoding(cursor, encoding_rs::UTF_8)
            .read_into(|key, value| {
                dst_map.insert(key, value);
            })
            .map_err(|e| CsrError::PropertiesRead {
                path: pathbuf.clone(),
                source: crate::Diagnostic::from_properties(e),
            })?;

        let req = |key: &str| -> Result<String, CsrError> {
            dst_map
                .get(key)
                .map(|s| s.to_string())
                .ok_or_else(|| CsrError::MissingProperty {
                    path: pathbuf.clone(),
                    key: key.to_string(),
                })
        };

        let csr = CsrProperties::new(
            req("csr.common.name")?,
            req("csr.serial.number")?,
            req("csr.organization.identifier")?,
            req("csr.organization.unit.name")?,
            req("csr.organization.name")?,
            req("csr.country.name")?,
            req("csr.invoice.type")?,
            req("csr.location.address")?,
            req("csr.industry.business.category")?,
        )?;

        Ok(csr)
    }

    /// Parse a CSR properties string.
    ///
    /// # Errors
    /// Returns [`CsrError`] when the properties cannot be read or required fields are missing.
    pub fn parse_csr_config(properties: &str) -> Result<CsrProperties, CsrError> {
        Self::from_properties_str(properties)
    }

    /// Parse a CSR properties file.
    ///
    /// # Errors
    /// Returns [`CsrError`] when the file cannot be read or required fields are missing.
    pub fn parse_csr_config_file(
        csr_path: impl AsRef<path::Path>,
    ) -> Result<CsrProperties, CsrError> {
        let path = csr_path.as_ref();
        let pathbuf = path.to_path_buf();
        let contents = std::fs::read_to_string(path).map_err(|e| CsrError::Io {
            path: pathbuf.clone(),
            source: e,
        })?;
        CsrProperties::from_properties_str(&contents).map_err(|mut error| {
            match &mut error {
                CsrError::PropertiesRead { path, .. } | CsrError::MissingProperty { path, .. } => {
                    *path = pathbuf
                }
                _ => {}
            }
            error
        })
    }
}

impl From<String> for CsrError {
    fn from(message: String) -> Self {
        CsrError::Validation { message }
    }
}
