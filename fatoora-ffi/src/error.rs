
use std::os::raw::c_char;

use crate::types::FfiString;
use fatoora_core::api::ZatcaError;
use fatoora_core::csr::CsrError;
use fatoora_core::invoice::{
    InvoiceError, QrCodeError,
};
use fatoora_core::invoice::sign::SigningError;
use fatoora_core::invoice::validation::XmlValidationError;
use fatoora_core::invoice::xml::InvoiceXmlError;
use fatoora_core::invoice::xml::parse::ParseError;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FfiErrorKind {
    InvalidInput = 1,
    Validation = 2,
    Parse = 3,
    Xml = 4,
    Crypto = 5,
    Io = 6,
    Network = 7,
    Unauthorized = 8,
    NotFound = 9,
    Internal = 10,
    Api = 11,
}

#[repr(C)]
pub struct FfiError {
    pub code: i32,
    pub message: *mut c_char,
}

#[derive(Debug)]
pub struct FfiErrorDetails {
    pub kind: FfiErrorKind,
    pub message: String,
}

impl FfiErrorDetails {
    pub fn new(kind: FfiErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[repr(C)]
pub struct FfiResult<T> {
    pub ok: bool,
    pub value: T,
    pub error: *mut FfiError,
}

impl<T> FfiResult<T> {
    pub fn ok(value: T) -> Self {
        Self {
            ok: true,
            value,
            error: std::ptr::null_mut(),
        }
    }

    pub fn err(details: FfiErrorDetails) -> Self {
        let c = std::ffi::CString::new(details.message).unwrap_or_else(|_| {
            std::ffi::CString::new("ffi error").expect("ffi error CString")
        });
        Self {
            ok: false,
            value: unsafe { std::mem::zeroed() },
            error: Box::into_raw(Box::new(FfiError {
                code: details.kind as i32,
                message: c.into_raw(),
            })),
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_error_free(error: *mut FfiError) {
    if !error.is_null() {
        let err = unsafe { Box::from_raw(error) };
        if !err.message.is_null() {
            unsafe { drop(std::ffi::CString::from_raw(err.message)) };
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_error_code(error: *mut FfiError) -> i32 {
    if error.is_null() {
        return 0;
    }
    unsafe { (*error).code }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_error_message(error: *mut FfiError) -> FfiString {
    if error.is_null() {
        return FfiString { ptr: std::ptr::null_mut() };
    }
    let message = unsafe { (*error).message };
    if message.is_null() {
        return FfiString { ptr: std::ptr::null_mut() };
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(message) };
    FfiString::from(cstr.to_string_lossy().to_string())
}

pub fn ffi_error_invalid_input(message: impl Into<String>) -> FfiErrorDetails {
    FfiErrorDetails::new(FfiErrorKind::InvalidInput, message)
}

pub fn ffi_error_internal(message: impl Into<String>) -> FfiErrorDetails {
    FfiErrorDetails::new(FfiErrorKind::Internal, message)
}

pub fn ffi_error_from_csr(err: CsrError) -> FfiErrorDetails {
    let kind = match err {
        CsrError::Io { .. } => FfiErrorKind::Io,
        CsrError::PropertiesRead { .. } => FfiErrorKind::Parse,
        CsrError::MissingProperty { .. } => FfiErrorKind::InvalidInput,
        CsrError::InvalidSubject { .. } => FfiErrorKind::InvalidInput,
        CsrError::InvalidSan { .. } => FfiErrorKind::InvalidInput,
        CsrError::RequestBuild { .. } => FfiErrorKind::Crypto,
        CsrError::AddExtension { .. } => FfiErrorKind::Crypto,
        CsrError::CsrBuild { .. } => FfiErrorKind::Crypto,
        CsrError::DerEncode { .. } => FfiErrorKind::Crypto,
        CsrError::Validation { .. } => FfiErrorKind::Validation,
    };
    FfiErrorDetails::new(kind, err.to_string())
}

pub fn ffi_error_from_invoice(err: InvoiceError) -> FfiErrorDetails {
    let kind = match err {
        InvoiceError::Validation(_) => FfiErrorKind::Validation,
        InvoiceError::InvalidCountryCode(_) => FfiErrorKind::InvalidInput,
        InvoiceError::MissingVatForSeller => FfiErrorKind::InvalidInput,
        InvoiceError::MissingBuyerId => FfiErrorKind::InvalidInput,
        InvoiceError::InvalidVatFormat => FfiErrorKind::InvalidInput,
    };
    FfiErrorDetails::new(kind, err.to_string())
}

pub fn ffi_error_from_signing(err: SigningError) -> FfiErrorDetails {
    FfiErrorDetails::new(FfiErrorKind::Crypto, err.to_string())
}

pub fn ffi_error_from_qr(err: QrCodeError) -> FfiErrorDetails {
    let kind = match err {
        QrCodeError::MissingSellerName => FfiErrorKind::InvalidInput,
        QrCodeError::MissingSellerVat => FfiErrorKind::InvalidInput,
        QrCodeError::ValueTooLong { .. } => FfiErrorKind::InvalidInput,
        QrCodeError::EncodedTooLong { .. } => FfiErrorKind::InvalidInput,
        QrCodeError::Xml(_) => FfiErrorKind::Xml,
    };
    FfiErrorDetails::new(kind, err.to_string())
}

pub fn ffi_error_from_xml(err: InvoiceXmlError) -> FfiErrorDetails {
    FfiErrorDetails::new(FfiErrorKind::Xml, err.to_string())
}

pub fn ffi_error_from_parse(err: ParseError) -> FfiErrorDetails {
    let kind = match err {
        ParseError::XmlParse(_) => FfiErrorKind::Xml,
        ParseError::XPath(_) => FfiErrorKind::Parse,
        ParseError::MissingField(_) => FfiErrorKind::InvalidInput,
        ParseError::InvalidValue { .. } => FfiErrorKind::InvalidInput,
    };
    FfiErrorDetails::new(kind, err.to_string())
}

pub fn ffi_error_from_validation(err: XmlValidationError) -> FfiErrorDetails {
    let kind = match err {
        XmlValidationError::FileNotFound { .. } => FfiErrorKind::NotFound,
        XmlValidationError::InvalidXsdPath { .. } => FfiErrorKind::InvalidInput,
        XmlValidationError::SchemaParse { .. } => FfiErrorKind::Parse,
        XmlValidationError::InvalidXmlPath { .. } => FfiErrorKind::InvalidInput,
        XmlValidationError::XmlParse { .. } => FfiErrorKind::Xml,
        XmlValidationError::SchemaValidation { .. } => FfiErrorKind::Validation,
    };
    FfiErrorDetails::new(kind, err.to_string())
}

pub fn ffi_error_from_api(err: ZatcaError) -> FfiErrorDetails {
    let kind = match err {
        ZatcaError::NetworkError(_) => FfiErrorKind::Network,
        ZatcaError::InvalidResponse(_) => FfiErrorKind::Parse,
        ZatcaError::Unauthorized(_) => FfiErrorKind::Unauthorized,
        ZatcaError::ServerError(_) => FfiErrorKind::Api,
        ZatcaError::Http(_) => FfiErrorKind::Network,
        ZatcaError::ClientState(_) => FfiErrorKind::Internal,
    };
    FfiErrorDetails::new(kind, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::{FfiErrorDetails, FfiErrorKind, FfiResult};

    #[test]
    fn ok_sets_error_null() {
        let result = FfiResult::ok(123u32);
        assert!(result.ok);
        assert!(result.error.is_null());
    }

    #[test]
    fn err_allocates_error() {
        let result = FfiResult::<u32>::err(FfiErrorDetails::new(
            FfiErrorKind::Internal,
            "boom",
        ));
        assert!(!result.ok);
        assert!(!result.error.is_null());
        unsafe { super::fatoora_error_free(result.error) };
    }
}
