pub mod api;
pub mod config;
pub mod csr;
pub mod invoice;

use thiserror::Error;

pub use config::EnvironmentParseError;
pub use csr::CsrError;
pub use invoice::{
    InvoiceError, InvoiceField, LineItemFields, LineItemPartsFields, LineItemTotalsFields,
    ValidationError, ValidationIssue, ValidationKind,
};
pub use invoice::QrCodeError;
pub use invoice::sign::SigningError;
pub use invoice::xml::InvoiceXmlError;
pub use invoice::xml::parse::ParseError;
pub use invoice::validation::XmlValidationError;
pub use api::ZatcaError;

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

