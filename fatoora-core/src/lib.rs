//! Rust toolkit for ZATCA Phase 1/2 e-invoicing (CSR, signing, validation, QR, and API).
//!
//! # Examples
//! ```rust
//! use fatoora_core::config::{Config, EnvironmentType};
//!
//! let config = Config::new(EnvironmentType::NonProduction);
//! # let _ = config;
//! ```
pub mod api;
pub mod config;
pub mod csr;
pub mod invoice;

/// Stable error kinds used across the core and FFI layers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    InvalidInput = 1,
    Validation = 2,
    Parse = 3,
    Xml = 4,
    Crypto = 5,
    Io = 6,
    Network = 7,
    Unauthorized = 8,
    Internal = 9,
    Api = 10,
}

/// Unified error type for the core library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

impl From<config::EnvironmentParseError> for Error {
    fn from(err: config::EnvironmentParseError) -> Self {
        Error::new(ErrorKind::InvalidInput, err.to_string())
    }
}

impl From<csr::CsrError> for Error {
    fn from(err: csr::CsrError) -> Self {
        let kind = match err {
            csr::CsrError::Io { .. } => ErrorKind::Io,
            csr::CsrError::PropertiesRead { .. } => ErrorKind::Parse,
            csr::CsrError::MissingProperty { .. } => ErrorKind::InvalidInput,
            csr::CsrError::InvalidSubject { .. } => ErrorKind::InvalidInput,
            csr::CsrError::InvalidSan { .. } => ErrorKind::InvalidInput,
            csr::CsrError::RequestBuild { .. } => ErrorKind::Crypto,
            csr::CsrError::AddExtension { .. } => ErrorKind::Crypto,
            csr::CsrError::CsrBuild { .. } => ErrorKind::Crypto,
            csr::CsrError::DerEncode { .. } => ErrorKind::Crypto,
            csr::CsrError::KeyDecode { .. } => ErrorKind::InvalidInput,
            csr::CsrError::KeyEncode { .. } => ErrorKind::Crypto,
            csr::CsrError::Validation { .. } => ErrorKind::Validation,
        };
        Error::new(kind, err.to_string())
    }
}

impl From<invoice::InvoiceError> for Error {
    fn from(err: invoice::InvoiceError) -> Self {
        let kind = match err {
            invoice::InvoiceError::Validation(_) => ErrorKind::Validation,
            invoice::InvoiceError::InvalidCountryCode(_)
            | invoice::InvoiceError::InvalidCurrencyCode(_)
            | invoice::InvoiceError::InvalidTimestamp(_)
            | invoice::InvoiceError::InvalidIssueDate(_)
            | invoice::InvoiceError::MissingVatForSeller
            | invoice::InvoiceError::MissingBuyerId
            | invoice::InvoiceError::InvalidVatFormat => ErrorKind::InvalidInput,
        };
        Error::new(kind, err.to_string())
    }
}

impl From<invoice::sign::SigningError> for Error {
    fn from(err: invoice::sign::SigningError) -> Self {
        Error::new(ErrorKind::Crypto, err.to_string())
    }
}

impl From<invoice::QrCodeError> for Error {
    fn from(err: invoice::QrCodeError) -> Self {
        let kind = match err {
            invoice::QrCodeError::MissingSellerName
            | invoice::QrCodeError::MissingSellerVat
            | invoice::QrCodeError::ValueTooLong { .. }
            | invoice::QrCodeError::EncodedTooLong { .. } => ErrorKind::InvalidInput,
            invoice::QrCodeError::Xml(_) => ErrorKind::Xml,
        };
        Error::new(kind, err.to_string())
    }
}

impl From<invoice::xml::InvoiceXmlError> for Error {
    fn from(err: invoice::xml::InvoiceXmlError) -> Self {
        Error::new(ErrorKind::Xml, err.to_string())
    }
}

impl From<invoice::xml::parse::ParseError> for Error {
    fn from(err: invoice::xml::parse::ParseError) -> Self {
        let kind = match err {
            invoice::xml::parse::ParseError::XmlParse(_) => ErrorKind::Xml,
            invoice::xml::parse::ParseError::XPath(_) => ErrorKind::Parse,
            invoice::xml::parse::ParseError::MissingField(_)
            | invoice::xml::parse::ParseError::InvalidValue { .. } => ErrorKind::InvalidInput,
        };
        Error::new(kind, err.to_string())
    }
}

impl From<invoice::validation::XmlValidationError> for Error {
    fn from(err: invoice::validation::XmlValidationError) -> Self {
        let kind = match err {
            invoice::validation::XmlValidationError::InvalidXsdPath { .. } => {
                ErrorKind::InvalidInput
            }
            invoice::validation::XmlValidationError::SchemaParse { .. } => ErrorKind::Parse,
            invoice::validation::XmlValidationError::XmlParse { .. } => ErrorKind::Xml,
            invoice::validation::XmlValidationError::SchemaValidation { .. } => {
                ErrorKind::Validation
            }
        };
        Error::new(kind, err.to_string())
    }
}

impl From<api::ZatcaError> for Error {
    fn from(err: api::ZatcaError) -> Self {
        let kind = match err {
            api::ZatcaError::NetworkError(_) => ErrorKind::Network,
            api::ZatcaError::InvalidResponse(_) => ErrorKind::Parse,
            api::ZatcaError::Unauthorized(_) => ErrorKind::Unauthorized,
            api::ZatcaError::ServerError(_) => ErrorKind::Api,
            api::ZatcaError::Http(_) => ErrorKind::Network,
            api::ZatcaError::ClientState(_) => ErrorKind::Internal,
        };
        Error::new(kind, err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind};
    use crate::invoice::sign::SigningError;
    use crate::invoice::validation::XmlValidationError;
    use crate::invoice::xml::InvoiceXmlError;
    use crate::invoice::xml::parse::ParseError;
    use crate::{
        api::ZatcaError,
        csr::CsrError,
        invoice::{
            InvoiceError, InvoiceField, QrCodeError, ValidationError, ValidationIssue,
            ValidationKind,
        },
    };
    use quick_xml::se::SeError;

    #[test]
    fn error_conversions_cover_variants() {
        let invoice_err =
            InvoiceError::Validation(ValidationError::new(vec![ValidationIssue::new(
                InvoiceField::Id,
                ValidationKind::Missing,
                None,
            )]));
        let err: Error = invoice_err.into();
        assert_eq!(err.kind(), ErrorKind::Validation);

        let err: Error = SigningError::SigningError("sign".into()).into();
        assert_eq!(err.kind(), ErrorKind::Crypto);

        let err: Error = QrCodeError::MissingSellerName.into();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);

        let xml_err = InvoiceXmlError::Serialize {
            source: SeError::Custom("xml".into()),
        };
        let err: Error = xml_err.into();
        assert_eq!(err.kind(), ErrorKind::Xml);

        let err: Error = ParseError::MissingField("uuid").into();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);

        let err: Error = XmlValidationError::XmlParse {
            message: "bad".into(),
        }
        .into();
        assert_eq!(err.kind(), ErrorKind::Xml);

        let err: Error = ZatcaError::ClientState("state".into()).into();
        assert_eq!(err.kind(), ErrorKind::Internal);

        let err: Error = CsrError::Validation {
            message: "csr".into(),
        }
        .into();
        assert_eq!(err.kind(), ErrorKind::Validation);
    }
}

#[cfg(test)]
mod fixture_hash_sign;
