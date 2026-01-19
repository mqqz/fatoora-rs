
#[repr(C)]
pub struct FfiResult<T> {
    pub ok: bool,
    pub value: T,
    pub error: *mut std::os::raw::c_char,
}

impl<T> FfiResult<T> {
    pub fn ok(value: T) -> Self {
        Self {
            ok: true,
            value,
            error: std::ptr::null_mut(),
        }
    }

    pub fn err(message: String) -> Self {
        let c = std::ffi::CString::new(message).unwrap_or_else(|_| {
            std::ffi::CString::new("ffi error").expect("ffi error CString")
        });
        Self {
            ok: false,
            value: unsafe { std::mem::zeroed() },
            error: c.into_raw(),
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
pub unsafe extern "C" fn fatoora_error_free(error: *mut std::os::raw::c_char) {
    if !error.is_null() {
        unsafe { drop(std::ffi::CString::from_raw(error)) };
    }
}

#[cfg(test)]
mod tests {
    use super::FfiResult;

    #[test]
    fn ok_sets_error_null() {
        let result = FfiResult::ok(123u32);
        assert!(result.ok);
        assert!(result.error.is_null());
    }

    #[test]
    fn err_allocates_error() {
        let result = FfiResult::<u32>::err("boom".to_string());
        assert!(!result.ok);
        assert!(!result.error.is_null());
        unsafe { drop(std::ffi::CString::from_raw(result.error)) };
    }
}
