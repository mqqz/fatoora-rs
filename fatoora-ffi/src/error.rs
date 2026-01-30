
use std::os::raw::c_char;

use crate::types::FfiString;
use fatoora_core::api::ZatcaError;
use fatoora_core::csr::CsrError;
use fatoora_core::invoice::{InvoiceError, QrCodeError};
use fatoora_core::invoice::sign::SigningError;
use fatoora_core::invoice::validation::XmlValidationError;
use fatoora_core::invoice::xml::InvoiceXmlError;
use fatoora_core::invoice::xml::parse::ParseError;
use fatoora_core::{Error as CoreError, ErrorKind};

pub type FfiErrorKind = ErrorKind;

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
        let c = std::ffi::CString::new(details.message).ok();
        Self {
            ok: false,
            value: unsafe { std::mem::zeroed() },
            error: Box::into_raw(Box::new(FfiError {
                code: details.kind as i32,
                message: c.map(|value| value.into_raw()).unwrap_or(std::ptr::null_mut()),
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
    match cstr.to_str() {
        Ok(value) => FfiString::from(value.to_string()),
        Err(_) => FfiString { ptr: std::ptr::null_mut() },
    }
}

pub fn ffi_error_invalid_input(message: impl Into<String>) -> FfiErrorDetails {
    FfiErrorDetails::new(FfiErrorKind::InvalidInput, message)
}

pub fn ffi_error_internal(message: impl Into<String>) -> FfiErrorDetails {
    FfiErrorDetails::new(FfiErrorKind::Internal, message)
}

pub fn ffi_error_from_core(err: CoreError) -> FfiErrorDetails {
    FfiErrorDetails::new(err.kind(), err.message().to_string())
}

pub fn ffi_error_from_csr(err: CsrError) -> FfiErrorDetails {
    ffi_error_from_core(err.into())
}

pub fn ffi_error_from_invoice(err: InvoiceError) -> FfiErrorDetails {
    ffi_error_from_core(err.into())
}

pub fn ffi_error_from_signing(err: SigningError) -> FfiErrorDetails {
    ffi_error_from_core(err.into())
}

pub fn ffi_error_from_qr(err: QrCodeError) -> FfiErrorDetails {
    ffi_error_from_core(err.into())
}

pub fn ffi_error_from_xml(err: InvoiceXmlError) -> FfiErrorDetails {
    ffi_error_from_core(err.into())
}

pub fn ffi_error_from_parse(err: ParseError) -> FfiErrorDetails {
    ffi_error_from_core(err.into())
}

pub fn ffi_error_from_validation(err: XmlValidationError) -> FfiErrorDetails {
    ffi_error_from_core(err.into())
}

pub fn ffi_error_from_api(err: ZatcaError) -> FfiErrorDetails {
    ffi_error_from_core(err.into())
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
