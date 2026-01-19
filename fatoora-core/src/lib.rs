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

use thiserror::Error;

// pub use config::EnvironmentParseError;
// pub use csr::CsrError;
// pub use invoice::{
//     InvoiceError, InvoiceField, LineItemFields, LineItemPartsFields, LineItemTotalsFields,
//     ValidationError, ValidationIssue, ValidationKind,
// };
// pub use invoice::QrCodeError;
// pub use invoice::sign::SigningError;
// pub use invoice::xml::InvoiceXmlError;
// pub use invoice::xml::parse::ParseError;
// pub use invoice::validation::XmlValidationError;
// pub use api::ZatcaError;

/// Top-level error wrapper for core operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Invoice(#[from] invoice::InvoiceError),
    #[error(transparent)]
    Signing(#[from] invoice::sign::SigningError),
    #[error(transparent)]
    Qr(#[from] invoice::QrCodeError),
    #[error(transparent)]
    Xml(#[from] invoice::xml::InvoiceXmlError),
    #[error(transparent)]
    Parse(#[from] invoice::xml::parse::ParseError),
    #[error(transparent)]
    XmlValidation(#[from] invoice::validation::XmlValidationError),
    #[error(transparent)]
    Api(#[from] api::ZatcaError),
    #[error(transparent)]
    Csr(#[from] csr::CsrError),
}

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::{
        api::ZatcaError,
        csr::CsrError,
        invoice::{
            InvoiceError, QrCodeError, ValidationError, ValidationIssue, ValidationKind,
            InvoiceField,
        },
    };
    use crate::invoice::sign::SigningError;
    use crate::invoice::xml::InvoiceXmlError;
    use crate::invoice::xml::parse::ParseError;
    use crate::invoice::validation::XmlValidationError;
    use quick_xml::se::SeError;

    #[test]
    fn error_conversions_cover_variants() {
        let invoice_err = InvoiceError::Validation(ValidationError::new(vec![
            ValidationIssue {
                field: InvoiceField::Id,
                kind: ValidationKind::Missing,
                line_item_index: None,
            },
        ]));
        let err: Error = invoice_err.into();
        assert!(matches!(err, Error::Invoice(_)));

        let err: Error = SigningError::SigningError("sign".into()).into();
        assert!(matches!(err, Error::Signing(_)));

        let err: Error = QrCodeError::MissingSellerName.into();
        assert!(matches!(err, Error::Qr(_)));

        let xml_err = InvoiceXmlError::Serialize {
            source: SeError::Custom("xml".into()),
        };
        let err: Error = xml_err.into();
        assert!(matches!(err, Error::Xml(_)));

        let err: Error = ParseError::MissingField("uuid").into();
        assert!(matches!(err, Error::Parse(_)));

        let err: Error = XmlValidationError::InvalidXmlPath {
            path: "bad".into(),
        }
        .into();
        assert!(matches!(err, Error::XmlValidation(_)));

        let err: Error = ZatcaError::ClientState("state".into()).into();
        assert!(matches!(err, Error::Api(_)));

        let err: Error = CsrError::Validation {
            message: "csr".into(),
        }
        .into();
        assert!(matches!(err, Error::Csr(_)));
    }
}
