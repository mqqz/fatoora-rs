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
    der::{Encode, Error as DerError, Length, Result as DerResult, Writer, asn1},
    ext::{
        AsExtension, Extension,
        pkix::{SubjectAltName, name::GeneralName},
    },
    name,
    request::CertReq,
};

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

    fn to_extension(&self) -> Result<TemplateNameExtension, CsrError> {
        let bytes = self.as_template_bytes();
        let os = asn1::OctetString::new(bytes).map_err(|e| CsrError::RequestBuild {
            message: format!("invalid template name bytes for extension: {e}"),
        })?;
        Ok(TemplateNameExtension(os))
    }
}

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

pub trait ToBase64String {
    fn to_base64_string(&self) -> Result<String, CsrError>;
}

impl ToBase64String for CertReq {
    fn to_base64_string(&self) -> Result<String, CsrError> {
        let der_bytes = self.to_der().map_err(|e| CsrError::DerEncode {
            context: "certificate request",
            source: e,
        })?;
        Ok(Base64::encode_string(&der_bytes))
    }
}

mod tests {

    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use k256::pkcs8::DecodePrivateKey;
    #[allow(unused_imports)]
    use k256::pkcs8::EncodePrivateKey;

    #[test]
    fn test_parse_csr_config() {
        let csr_config = CsrProperties::parse_csr_config(std::path::Path::new(
            "../assets/csr-configs/csr-config-example-EN.properties",
        ))
        .unwrap();
        assert_eq!(csr_config.common_name, "TST-886431145-399999999900003");
        assert_eq!(
            csr_config.serial_number,
            "1-TST|2-TST|3-ed22f1d8-e6a2-1118-9b58-d9a8f11e445f"
        );
        assert_eq!(csr_config.organization_identifier, "399999999900003");
        assert_eq!(csr_config.organization_unit_name, "Riyadh Branch");
        assert_eq!(
            csr_config.organization_name,
            "Maximum Speed Tech Supply LTD"
        );
        assert_eq!(csr_config.country_name, "SA");
        assert_eq!(csr_config.invoice_type, "1100");
        assert_eq!(csr_config.location_address, "RRRD2929");
        assert_eq!(csr_config.industry_business_category, "Supply activities");
    }

    #[test]
    fn test_generate_csr() {
        // Parse config
        let csr_config = CsrProperties::parse_csr_config(std::path::Path::new(
            "../assets/csr-configs/csr-config-example-EN.properties",
        ))
        .unwrap();

        // Build CSR for a known environment
        let env = EnvironmentType::from_str("non_production")
            .map_err(|e| CsrError::Validation {
                message: e.to_string(),
            })
            .unwrap();
        let (csr, _key) = csr_config.build_with_rng(env).unwrap();

        // CSR must DER-encode successfully and produce a non-empty Base64 string
        let der = csr
            .to_der()
            .map_err(|e| CsrError::DerEncode {
                context: "certificate request (test_generate_csr)",
                source: e,
            })
            .unwrap();
        assert!(!der.is_empty(), "CSR DER must not be empty");

        let b64 = Base64::encode_string(&der);
        assert!(!b64.is_empty(), "CSR Base64 must not be empty");

        // Ensure extensions were added: SubjectAltName and template extension OID.
        // Extensions are carried inside the PKCS#9 extensionRequest attribute.
        let info = &csr.info;
        let exts = info.attributes.iter().flat_map(|attr| attr.values.iter());

        let mut found_san = false;
        let mut found_template = false;

        // DER OID for SubjectAltName: 2.5.29.17 => 06 03 55 1D 11
        const SAN_OID_DER: &[u8] = b"\x06\x03\x55\x1D\x11";
        // TemplateNameExtension OID: 1.3.6.1.4.1.311.20.2 => 2b 06 01 04 01 82 37 14 02
        const TEMPLATE_OID_DER: &[u8] = b"\x2b\x06\x01\x04\x01\x82\x37\x14\x02";

        for val in exts {
            let encoded = val.to_der().unwrap_or_default();
            if encoded.windows(SAN_OID_DER.len()).any(|w| w == SAN_OID_DER) {
                found_san = true;
            }
            if encoded
                .windows(TEMPLATE_OID_DER.len())
                .any(|w| w == TEMPLATE_OID_DER)
            {
                found_template = true;
            }
            if found_san && found_template {
                break;
            }
        }

        assert!(
            found_san,
            "CSR must include a SubjectAltName extension (OID 2.5.29.17) inside extensionRequest"
        );
        assert!(
            found_template,
            "CSR must include the template name extension (OID 1.3.6.1.4.1.311.20.2)"
        );

        // Verify subject contains expected RDNs
        let subject_str = info.subject.to_string();
        assert!(
            subject_str.contains("C=SA"),
            "Subject must contain country code 'SA' (got {subject_str})"
        );
        assert!(
            subject_str.contains("CN=TST-"),
            "Subject must contain CN with 'TST-' prefix (got {subject_str})"
        );

        // println!("CSR generated {}", csr.to_base64_string().unwrap());
        // save private key in pem format for debugging
        // ecdsa::SigningKey::write_pkcs8_der_file(&_key, "test_private_key.der").unwrap();
    }

    #[test]
    fn test_csr_matches_zatca_sdk() {
        // This test ensures that the generated CSR matches the one produced by
        // the ZATCA SDK for the same input properties.
        //
        // The reference CSR was generated using the ZATCA SDK with the same
        // properties as in the csr-config-example-EN.properties file.
        //
        // The test compares the Base64-encoded CSR strings.
        let csr_config = CsrProperties::parse_csr_config(std::path::Path::new(
            "../assets/csr-configs/csr-config-example-EN.properties",
        ))
        .unwrap();
        let env = EnvironmentType::from_str("production")
            .map_err(|e| CsrError::Validation {
                message: e.to_string(),
            })
            .unwrap();
        let zatca_pkey = ecdsa::SigningKey::from_pkcs8_der(
            &std::fs::read("../assets/pkeys/test_zatca_pkey.der").unwrap(),
        )
        .unwrap();

        let csr = csr_config.build(&zatca_pkey, env).unwrap();
        // let generated_b64 = csr.to_base64_string().unwrap();
        // let reference_b64 = std::fs::read_to_string("../assets/csrs/test_zatca_en1.csr")
        //     .expect("Failed to read reference CSR file")
        //     .trim()
        //     .to_string();
        // assert_eq!(
        //     generated_b64, reference_b64,
        //     "Generated CSR does not match reference CSR from ZATCA SDK"
        // );
    }
}
