pub mod api;
pub mod config;
pub mod csr;
pub mod invoice;

use thiserror::Error;

pub use config::EnvironmentParseError;
pub use csr::CsrError;
pub use invoice::{
    InvoiceError, InvoiceField, ValidationError, ValidationIssue, ValidationKind,
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

// Central SDK version
pub const FATOORA_VERSION: &str = "0.1.0";

use std::os::raw::c_char;

/// Return static version string.
#[unsafe(no_mangle)]
pub extern "C" fn fatoora_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_static() {
        // Calls raw Rust version, not ABI
        assert_eq!(fatoora_version(), b"0.1.0\0".as_ptr() as _);
    }
}
