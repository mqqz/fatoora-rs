use crate::types::FfiString;
use fatoora_core::Error as CoreError;
use fatoora_core::api::ZatcaError;
use fatoora_core::csr::CsrError;
use fatoora_core::invoice::sign::SigningError;
use fatoora_core::invoice::validation::XmlValidationError;
use fatoora_core::invoice::xml::InvoiceXmlError;
use fatoora_core::invoice::xml::parse::ParseError;
use fatoora_core::invoice::{InvoiceError, QrCodeError};

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FfiErrorKind {
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

/// Opaque error handle. Inspect through accessors and release with `fatoora_error_free`.
/// Its Rust layout is intentionally not part of the C ABI.
pub struct FfiError {
    details: FfiErrorDetails,
}

#[derive(Debug)]
pub struct FfiErrorDetails {
    code: i32,
    message: String,
    details_json: String,
}

impl FfiErrorDetails {
    pub fn new(kind: FfiErrorKind, message: impl Into<String>) -> Self {
        Self {
            code: kind as i32,
            message: message.into(),
            details_json: r#"{"type":"error"}"#.into(),
        }
    }
    pub(crate) fn with_context(mut self, context: &str) -> Self {
        self.message = format!("{context}: {}", self.message);
        self
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

    pub fn err(details: FfiErrorDetails) -> Self
    where
        T: Default,
    {
        Self {
            ok: false,
            value: T::default(),
            error: Box::into_raw(Box::new(FfiError { details })),
        }
    }
}

/// Release an error handle. Null is accepted.
///
/// # Safety
/// `error` must be null or a live handle returned by this library, freed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fatoora_error_free(error: *mut FfiError) {
    if !error.is_null() {
        unsafe { drop(Box::from_raw(error)) };
    }
}

/// Read the stable numeric classification. Null returns zero (no error).
///
/// # Safety
/// `error` must be null or a live error handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fatoora_error_code(error: *mut FfiError) -> i32 {
    unsafe { error.as_ref() }.map_or(0, |error| error.details.code)
}

/// Copy the UTF-8 message. Free the returned string with `fatoora_string_free`.
/// The copy remains valid after the error handle is freed. Null returns a null string.
/// Embedded NUL characters are displayed as the two characters `\0`.
///
/// # Safety
/// `error` must be null or a live error handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fatoora_error_message(error: *mut FfiError) -> FfiString {
    match unsafe { error.as_ref() } {
        Some(error) => FfiString::from(error.details.message.replace('\0', "\\0")),
        None => FfiString {
            ptr: std::ptr::null_mut(),
        },
    }
}

/// Copy structured error details as UTF-8 JSON. Every object has a `type` field.
/// Consumers must tolerate unknown types and additional fields.
/// Free the returned string with `fatoora_string_free`; it remains valid after
/// the error handle is freed. Null returns a null string.
///
/// # Safety
/// `error` must be null or a live error handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fatoora_error_details_json(error: *mut FfiError) -> FfiString {
    match unsafe { error.as_ref() } {
        Some(error) => FfiString::from(error.details.details_json.clone()),
        None => FfiString {
            ptr: std::ptr::null_mut(),
        },
    }
}

pub fn ffi_error_invalid_input(message: impl Into<String>) -> FfiErrorDetails {
    FfiErrorDetails::new(FfiErrorKind::InvalidInput, message)
}

pub fn ffi_error_internal(message: impl Into<String>) -> FfiErrorDetails {
    FfiErrorDetails::new(FfiErrorKind::Internal, message)
}

pub fn ffi_error_from_core(err: CoreError) -> FfiErrorDetails {
    FfiErrorDetails {
        code: err.kind() as i32,
        message: err.to_string(),
        details_json: err.details_json(),
    }
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
        let result = FfiResult::<u32>::err(FfiErrorDetails::new(FfiErrorKind::Internal, "boom"));
        assert!(!result.ok);
        assert!(!result.error.is_null());
        unsafe { super::fatoora_error_free(result.error) };
    }
}

/// Catch unwinding panics before returning through C. Abort-mode panics and
/// allocation failure still terminate the process, as in any Rust library.
pub(crate) fn boundary<T: Default>(operation: impl FnOnce() -> FfiResult<T>) -> FfiResult<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(payload) => {
            // Release ordinary panic payloads. A custom payload may panic on
            // drop; contain that second panic and avoid dropping it recursively.
            if let Err(nested) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
            {
                std::mem::forget(nested);
            }
            FfiResult::err(ffi_error_internal("internal operation panicked"))
        }
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use crate::fatoora_string_free;
    use std::ffi::CStr;

    unsafe fn read_and_free(value: FfiString) -> String {
        let result = unsafe { CStr::from_ptr(value.ptr) }
            .to_str()
            .unwrap()
            .to_owned();
        unsafe { fatoora_string_free(value) };
        result
    }

    #[test]
    fn panic_becomes_internal_error() {
        let result = boundary::<u32>(|| panic!("test panic"));
        assert!(!result.ok);
        assert_eq!(result.value, 0);
        unsafe {
            assert_eq!(fatoora_error_code(result.error), 9);
            assert_eq!(
                read_and_free(fatoora_error_message(result.error)),
                "internal operation panicked"
            );
            assert_eq!(
                read_and_free(fatoora_error_details_json(result.error)),
                r#"{"type":"error"}"#
            );
            fatoora_error_free(result.error);
        }
    }

    #[test]
    fn null_handles_and_independent_string_ownership() {
        unsafe {
            assert_eq!(fatoora_error_code(std::ptr::null_mut()), 0);
            assert!(fatoora_error_message(std::ptr::null_mut()).ptr.is_null());
            assert!(
                fatoora_error_details_json(std::ptr::null_mut())
                    .ptr
                    .is_null()
            );
            fatoora_error_free(std::ptr::null_mut());
            let result = FfiResult::<u8>::err(ffi_error_from_api(ZatcaError::NetworkError(
                "خطأ\0end".into(),
            )));
            let message = fatoora_error_message(result.error);
            let details = fatoora_error_details_json(result.error);
            fatoora_error_free(result.error);
            assert_eq!(read_and_free(message), "Network error: خطأ\\0end");
            let details: serde_json::Value = serde_json::from_str(&read_and_free(details)).unwrap();
            assert_eq!(details["diagnostics"][0]["message"], "خطأ\0end");
        }
    }

    #[test]
    fn existing_category_codes_stay_in_sync() {
        use fatoora_core::ErrorKind;
        let pairs = [
            (ErrorKind::InvalidInput, FfiErrorKind::InvalidInput, 1),
            (ErrorKind::Validation, FfiErrorKind::Validation, 2),
            (ErrorKind::Parse, FfiErrorKind::Parse, 3),
            (ErrorKind::Xml, FfiErrorKind::Xml, 4),
            (ErrorKind::Crypto, FfiErrorKind::Crypto, 5),
            (ErrorKind::Io, FfiErrorKind::Io, 6),
            (ErrorKind::Network, FfiErrorKind::Network, 7),
            (ErrorKind::Unauthorized, FfiErrorKind::Unauthorized, 8),
            (ErrorKind::Internal, FfiErrorKind::Internal, 9),
            (ErrorKind::Api, FfiErrorKind::Api, 10),
        ];
        for (core, ffi, code) in pairs {
            assert_eq!(core as i32, code);
            assert_eq!(ffi as i32, code);
        }
    }
}

#[cfg(test)]
mod panic_payload_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Payload {
        dropped: Arc<AtomicBool>,
        panic_on_drop: bool,
    }
    impl Drop for Payload {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
            assert!(!self.panic_on_drop, "payload destructor panicked");
        }
    }

    #[test]
    fn panic_payloads_are_released_and_destructor_panics_are_contained() {
        for panic_on_drop in [false, true] {
            let dropped = Arc::new(AtomicBool::new(false));
            let payload = Payload {
                dropped: dropped.clone(),
                panic_on_drop,
            };
            let result = boundary::<u8>(|| std::panic::panic_any(payload));
            assert!(dropped.load(Ordering::SeqCst));
            assert!(!result.ok);
            unsafe {
                assert_eq!(
                    fatoora_error_code(result.error),
                    FfiErrorKind::Internal as i32
                );
                fatoora_error_free(result.error);
            }
        }
    }
}
