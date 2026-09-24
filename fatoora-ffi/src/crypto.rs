//! Owned configuration, CSR, key, and signing bindings.

#[diplomat::bridge]
#[diplomat::abi_rename = "fatoora_{0}"]
#[diplomat::attr(cpp, namespace = "fatoora")]
pub mod ffi {
    use crate::common::ffi::BindingError;
    use crate::common::{boundary, core_error, local_error, text, write};
    use crate::invoice::ffi::{FinalizedInvoice, SignedInvoice};
    use diplomat_runtime::{DiplomatStr, DiplomatWrite};

    #[diplomat::opaque]
    #[diplomat::attr(
        nanobind,
        custom_extra_code(file = "bytes_bindings.cpp", location = "init_block")
    )]
    pub struct Bytes(pub(crate) Vec<u8>);

    impl Bytes {
        /// The view is valid while this immutable owner remains alive.
        #[allow(clippy::needless_lifetimes)] // Diplomat requires an explicit return lifetime.
        pub fn as_slice<'a>(&'a self) -> &'a [u8] {
            &self.0
        }
    }

    #[diplomat::opaque]
    pub struct BytesList(pub(crate) Vec<Vec<u8>>);

    impl BytesList {
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
        pub fn get(&self, index: usize) -> Result<Box<Bytes>, Box<BindingError>> {
            boundary(|| {
                self.0
                    .get(index)
                    .cloned()
                    .map(|v| Box::new(Bytes(v)))
                    .ok_or_else(|| local_error(1, "byte list index out of bounds"))
            })
        }
    }

    #[diplomat::opaque]
    pub struct Config(pub(crate) fatoora_core::config::Config);

    impl Config {
        pub fn new(env: u8) -> Result<Box<Config>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(fatoora_core::config::Config::new(
                    crate::common::environment(env)?,
                ))))
            })
        }
        pub fn env(&self) -> u8 {
            match self.0.env() {
                fatoora_core::config::EnvironmentType::NonProduction => 0,
                fatoora_core::config::EnvironmentType::Simulation => 1,
                fatoora_core::config::EnvironmentType::Production => 2,
            }
        }
    }

    #[diplomat::opaque]
    pub struct SigningKey(pub(crate) fatoora_core::csr::SigningKey);

    impl SigningKey {
        pub fn generate() -> Result<Box<SigningKey>, Box<BindingError>> {
            boundary(|| Ok(Box::new(Self(fatoora_core::csr::SigningKey::generate()))))
        }
        pub fn from_pem(pem: &DiplomatStr) -> Result<Box<SigningKey>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(
                    fatoora_core::csr::SigningKey::from_pem(text(pem)?).map_err(core_error)?,
                )))
            })
        }
        pub fn from_der(der: &[u8]) -> Result<Box<SigningKey>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(
                    fatoora_core::csr::SigningKey::from_der(der).map_err(core_error)?,
                )))
            })
        }
        pub fn to_pem(&self, out: &mut DiplomatWrite) -> Result<(), Box<BindingError>> {
            boundary(|| write(&self.0.to_pem().map_err(core_error)?, out))
        }
        pub fn to_der(&self) -> Result<Box<Bytes>, Box<BindingError>> {
            boundary(|| Ok(Box::new(Bytes(self.0.to_der().map_err(core_error)?))))
        }
    }

    #[diplomat::opaque]
    pub struct CsrProperties(pub(crate) fatoora_core::csr::CsrProperties);

    impl CsrProperties {
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            common_name: &DiplomatStr,
            serial_number: &DiplomatStr,
            organization_identifier: &DiplomatStr,
            organization_unit_name: &DiplomatStr,
            organization_name: &DiplomatStr,
            country_name: &DiplomatStr,
            invoice_type: &DiplomatStr,
            location_address: &DiplomatStr,
            industry_business_category: &DiplomatStr,
        ) -> Result<Box<CsrProperties>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(
                    fatoora_core::csr::CsrProperties::new(
                        text(common_name)?.to_owned(),
                        text(serial_number)?.to_owned(),
                        text(organization_identifier)?.to_owned(),
                        text(organization_unit_name)?.to_owned(),
                        text(organization_name)?.to_owned(),
                        text(country_name)?.to_owned(),
                        text(invoice_type)?.to_owned(),
                        text(location_address)?.to_owned(),
                        text(industry_business_category)?.to_owned(),
                    )
                    .map_err(core_error)?,
                )))
            })
        }
        pub fn from_properties_str(
            properties: &DiplomatStr,
        ) -> Result<Box<CsrProperties>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(
                    fatoora_core::csr::CsrProperties::from_properties_str(text(properties)?)
                        .map_err(core_error)?,
                )))
            })
        }
        pub fn parse_csr_config_file(
            path: &DiplomatStr,
        ) -> Result<Box<CsrProperties>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(
                    fatoora_core::csr::CsrProperties::parse_csr_config_file(text(path)?)
                        .map_err(core_error)?,
                )))
            })
        }
        pub fn build(&self, key: &SigningKey, env: u8) -> Result<Box<Csr>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Csr(self
                    .0
                    .build(&key.0, crate::common::environment(env)?)
                    .map_err(core_error)?)))
            })
        }
    }

    #[diplomat::opaque]
    pub struct Csr(pub(crate) fatoora_core::csr::Csr);

    impl Csr {
        pub fn from_der(der: &[u8]) -> Result<Box<Csr>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(
                    fatoora_core::csr::Csr::from_der(der).map_err(core_error)?,
                )))
            })
        }
        pub fn to_der(&self) -> Result<Box<Bytes>, Box<BindingError>> {
            boundary(|| Ok(Box::new(Bytes(self.0.to_der().map_err(core_error)?))))
        }
        pub fn to_pem(&self, out: &mut DiplomatWrite) -> Result<(), Box<BindingError>> {
            boundary(|| write(&self.0.to_pem().map_err(core_error)?, out))
        }
        pub fn to_base64(&self, out: &mut DiplomatWrite) -> Result<(), Box<BindingError>> {
            boundary(|| write(&self.0.to_base64().map_err(core_error)?, out))
        }
        pub fn to_pem_base64(&self, out: &mut DiplomatWrite) -> Result<(), Box<BindingError>> {
            boundary(|| write(&self.0.to_pem_base64().map_err(core_error)?, out))
        }
        pub fn subject_string(&self, out: &mut DiplomatWrite) -> Result<(), Box<BindingError>> {
            boundary(|| write(self.0.subject_string(), out))
        }
        pub fn extension_values_der(&self) -> Result<Box<BytesList>, Box<BindingError>> {
            boundary(|| Ok(Box::new(BytesList(self.0.extension_values_der()))))
        }
    }

    #[diplomat::opaque]
    pub struct Signer(pub(crate) fatoora_core::invoice::sign::InvoiceSigner);

    impl Signer {
        pub fn from_pem(
            cert_pem: &DiplomatStr,
            key_pem: &DiplomatStr,
        ) -> Result<Box<Signer>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(
                    fatoora_core::invoice::sign::InvoiceSigner::from_pem(
                        text(cert_pem)?,
                        text(key_pem)?,
                    )
                    .map_err(core_error)?,
                )))
            })
        }
        pub fn from_der(cert_der: &[u8], key_der: &[u8]) -> Result<Box<Signer>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(
                    fatoora_core::invoice::sign::InvoiceSigner::from_der(cert_der, key_der)
                        .map_err(core_error)?,
                )))
            })
        }
        pub fn certificate_der(&self) -> Result<Box<Bytes>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Bytes(
                    self.0.certificate_der().map_err(core_error)?,
                )))
            })
        }
        pub fn certificate_pem(&self, out: &mut DiplomatWrite) -> Result<(), Box<BindingError>> {
            boundary(|| write(&self.0.certificate_pem().map_err(core_error)?, out))
        }
        pub fn sign(
            &self,
            invoice: &mut FinalizedInvoice,
        ) -> Result<Box<SignedInvoice>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(SignedInvoice(Some(
                    invoice
                        .0
                        .take()
                        .ok_or_else(|| local_error(1, "invoice has been consumed"))?
                        .sign(&self.0)
                        .map_err(core_error)?,
                ))))
            })
        }
        pub fn sign_xml(
            &self,
            xml: &DiplomatStr,
            out: &mut DiplomatWrite,
        ) -> Result<(), Box<BindingError>> {
            boundary(|| write(&self.0.sign_xml(text(xml)?).map_err(core_error)?, out))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ffi::{BytesList, Config, Csr, CsrProperties, Signer, SigningKey};

    #[test]
    fn configuration_rejects_unknown_environment() {
        for env in 0..=2 {
            assert_eq!(
                Config::new(env)
                    .unwrap_or_else(|_| panic!("operation should succeed"))
                    .env(),
                env
            );
        }
        assert!(Config::new(3).is_err());
        assert!(Config::new(u8::MAX).is_err());
    }

    #[test]
    fn signing_key_der_roundtrip_preserves_private_key() {
        let key = SigningKey::generate().unwrap_or_else(|_| panic!("operation should succeed"));
        let der = key
            .to_der()
            .unwrap_or_else(|_| panic!("operation should succeed"));
        let parsed = SigningKey::from_der(der.as_slice())
            .unwrap_or_else(|_| panic!("operation should succeed"));
        assert_eq!(
            parsed
                .to_der()
                .unwrap_or_else(|_| panic!("operation should succeed"))
                .as_slice(),
            der.as_slice()
        );
    }

    #[test]
    fn invalid_keys_and_certificates_return_errors() {
        assert!(SigningKey::from_der(&[]).is_err());
        assert!(SigningKey::from_pem(b"invalid pem").is_err());
        assert!(SigningKey::from_pem(b"invalid\0pem").is_err());
        assert!(SigningKey::from_pem(&[0xff]).is_err());
        assert!(Csr::from_der(&[]).is_err());
        assert!(Signer::from_der(&[], &[]).is_err());
        assert!(Signer::from_pem(b"invalid", b"invalid").is_err());
        assert!(CsrProperties::from_properties_str(b"bad=1").is_err());
        assert!(CsrProperties::parse_csr_config_file(b"bad\0path").is_err());
    }

    #[test]
    fn byte_list_returns_independent_owned_values_and_checks_bounds() {
        let list = BytesList(vec![vec![0, 255, 1], vec![]]);
        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
        let bytes = list
            .get(0)
            .unwrap_or_else(|_| panic!("operation should succeed"));
        assert!(
            list.get(1)
                .unwrap_or_else(|_| panic!("operation should succeed"))
                .as_slice()
                .is_empty()
        );
        assert!(list.get(2).is_err());
        assert!(list.get(usize::MAX).is_err());
        drop(list);
        assert_eq!(bytes.as_slice(), &[0, 255, 1]);
    }
}
