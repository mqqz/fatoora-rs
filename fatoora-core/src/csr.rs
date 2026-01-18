//! CSR generation and helpers.
use crate::config::EnvironmentType;
use base64ct::{Base64, Encoding};
use ecdsa;
use fatoora_derive::Validate;
use java_properties::read;
use k256::{Secp256k1, ecdsa::SigningKey};
use std::{
    fs::File,
    io::BufReader,
    path::{self, PathBuf},
    str::FromStr,
    vec,
};
use thiserror::Error;
use x509_cert::{
    builder::{Builder, RequestBuilder},
    der::{
        Encode, EncodePem, Error as DerError, Length, Result as DerResult, Writer, asn1,
        pem::LineEnding,
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
        source: java_properties::PropertiesError,
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

    #[error("failed DER encoding for {context}: {source}")]
    DerEncode {
        context: &'static str,
        #[source]
        source: DerError,
    },

    #[error("validation error: {message}")]
    Validation { message: String },
}

struct TemplateNameExtension(pub asn1::OctetString);

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
        let os = asn1::OctetString::new(bytes).map_err(|e| CsrError::RequestBuild {
            message: format!("invalid template name bytes for extension: {e}"),
        })?;
        Ok(TemplateNameExtension(os))
    }
}

/// CSR properties parsed from the SDK properties file.
///
/// # Examples
/// ```rust,no_run
/// use fatoora_core::config::EnvironmentType;
/// use fatoora_core::csr::CsrProperties;
///
/// let props = CsrProperties::parse_csr_config("csr.properties".as_ref())?;
/// let (csr, _key) = props.build_with_rng(EnvironmentType::NonProduction)?;
/// # let _ = csr;
/// # Ok::<(), fatoora_core::CsrError>(())
/// ```
#[allow(dead_code)]
#[derive(Validate, Debug)]
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
    invoice_type: String,
    location_address: String,
    industry_business_category: String,
}

impl CsrProperties {
    fn generate_subject(&self) -> Result<name::Name, CsrError> {
        name::Name::from_str(&format!(
            "C={},OU={},O={},CN={}",
            &self.country_name,
            &self.organization_unit_name,
            &self.organization_name,
            &self.common_name
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
            "sn={},uid={},title={},registeredAddress={},businessCategory={}",
            &self.serial_number,
            &self.organization_identifier,
            &self.invoice_type,
            &self.location_address,
            &self.industry_business_category
        ))
        .map_err(|e| CsrError::InvalidSan {
            message: e.to_string(),
        })?;
        let dir_name = GeneralName::DirectoryName(name);
        Ok(SubjectAltName::from(vec![dir_name]))
    }

    fn generate_signer(&self) -> ecdsa::SigningKey<Secp256k1> {
        ecdsa::SigningKey::<Secp256k1>::generate()
    }

    pub fn build(&self, signer: &SigningKey, env: EnvironmentType) -> Result<CertReq, CsrError> {
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
            .build::<_, ecdsa::der::Signature<_>>(signer)
            .map_err(|e| CsrError::CsrBuild {
                message: e.to_string(),
            })
    }

    pub fn build_with_rng(&self, env: EnvironmentType) -> Result<(CertReq, SigningKey), CsrError> {
        let signer: ecdsa::SigningKey<Secp256k1> = self.generate_signer();
        let csr = self.build(&signer, env)?;
        Ok((csr, signer))
    }

    pub fn parse_csr_config(csr_path: &path::Path) -> Result<CsrProperties, CsrError> {
        let pathbuf = csr_path.to_path_buf();
        let file = File::open(csr_path).map_err(|e| CsrError::Io {
            path: pathbuf.clone(),
            source: e,
        })?;
        let dst_map = read(BufReader::new(file)).map_err(|e| CsrError::PropertiesRead {
            path: pathbuf.clone(),
            source: e,
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
}

impl From<String> for CsrError {
    fn from(message: String) -> Self {
        CsrError::Validation { message }
    }
}

/// Encode to base64 string.
pub trait ToBase64String {
    fn to_base64_string(&self) -> Result<String, CsrError>;
    fn to_pem_base64_string(&self) -> Result<String, CsrError>;
}

impl ToBase64String for CertReq {
    fn to_base64_string(&self) -> Result<String, CsrError> {
        let der_bytes = self.to_der().map_err(|e| CsrError::DerEncode {
            context: "certificate request",
            source: e,
        })?;
        Ok(Base64::encode_string(&der_bytes))
    }

    fn to_pem_base64_string(&self) -> Result<String, CsrError> {
        let pem = self
            .to_pem(LineEnding::LF)
            .map_err(|e| CsrError::DerEncode {
                context: "certificate request (PEM)",
                source: e,
            })?;
        Ok(Base64::encode_string(pem.as_bytes()))
    }
}
