//! Crate-owned errors and backend diagnostics.
use crate::{api, config, csr, invoice};

mod details;

/// Backend diagnostic text and optional source location.
/// Messages are for people; their wording is not a stable API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct Diagnostic {
    message: String,
    file: Option<String>,
    line: Option<u32>,
    column: Option<u32>,
    severity: Option<DiagnosticSeverity>,
}

impl Diagnostic {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            file: None,
            line: None,
            column: None,
            severity: None,
        }
    }
    pub fn message(&self) -> &str {
        &self.message
    }
    pub fn file(&self) -> Option<&str> {
        self.file.as_deref()
    }
    /// One-based line number, when provided by the backend.
    pub fn line(&self) -> Option<u32> {
        self.line
    }
    /// One-based column number, when provided by the backend.
    pub fn column(&self) -> Option<u32> {
        self.column
    }

    pub fn severity(&self) -> Option<DiagnosticSeverity> {
        self.severity
    }

    pub(crate) fn from_properties(error: java_properties::PropertiesError) -> Self {
        Self {
            line: error
                .line_number()
                .and_then(|line| u32::try_from(line).ok())
                .filter(|line| *line > 0),
            ..Self::new(error.to_string())
        }
    }

    pub(crate) fn from_xml(error: libxml::error::StructuredError) -> Self {
        Self {
            message: error.message.unwrap_or_else(|| "XML error".into()),
            file: error.filename,
            severity: match error.level {
                libxml::error::XmlErrorLevel::None => None,
                libxml::error::XmlErrorLevel::Warning => Some(DiagnosticSeverity::Warning),
                libxml::error::XmlErrorLevel::Error => Some(DiagnosticSeverity::Error),
                libxml::error::XmlErrorLevel::Fatal => Some(DiagnosticSeverity::Fatal),
            },
            line: error
                .line
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n > 0),
            column: error
                .col
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n > 0),
        }
    }
}

/// Severity reported by a diagnostic backend.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Warning,
    Error,
    Fatal,
}

/// Stable error kinds used across the core and FFI layers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
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

/// An error retaining the structured failure from its originating module.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Environment(#[from] config::EnvironmentParseError),
    #[error("{0}")]
    Decimal(#[from] crate::DecimalError),
    #[error("{0}")]
    Csr(#[from] csr::CsrError),
    #[error("{0}")]
    Invoice(#[from] invoice::InvoiceError),
    #[error("{0}")]
    Signing(#[from] invoice::sign::SigningError),
    #[error("{0}")]
    Qr(#[from] invoice::QrCodeError),
    #[error("{0}")]
    Xml(#[from] invoice::xml::InvoiceXmlError),
    #[error("{0}")]
    Parse(#[from] invoice::xml::parse::ParseError),
    #[error("{0}")]
    XmlValidation(#[from] invoice::validation::XmlValidationError),
    #[error("{0}")]
    Api(#[from] api::ZatcaError),
}

impl Error {
    /// Shared classification used by bindings.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Environment(err) => err.kind(),
            Self::Decimal(err) => err.kind(),
            Self::Csr(err) => err.kind(),
            Self::Invoice(err) => err.kind(),
            Self::Signing(err) => err.kind(),
            Self::Qr(err) => err.kind(),
            Self::Xml(err) => err.kind(),
            Self::Parse(err) => err.kind(),
            Self::XmlValidation(err) => err.kind(),
            Self::Api(err) => err.kind(),
        }
    }
}
