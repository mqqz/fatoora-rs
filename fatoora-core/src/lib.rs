//! Rust toolkit for ZATCA Phase 1/2 e-invoicing (CSR, signing, validation, QR, and API).
//!
//! # Examples
//! ```rust
//! use fatoora_core::config::{Config, EnvironmentType};
//!
//! let config = Config::new(EnvironmentType::NonProduction);
//! # let _ = config;
//! ```
mod error;
pub use error::{Diagnostic, DiagnosticSeverity, Error, ErrorKind};
mod decimal;
pub use decimal::{Decimal, DecimalError};
pub mod api;
pub mod config;
pub mod csr;
pub mod invoice;

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind};
    use crate::Diagnostic;
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
            source: Diagnostic::new("xml"),
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
