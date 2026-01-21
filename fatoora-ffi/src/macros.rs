macro_rules! ffi_require_handle {
    ($ptr:expr, $label:literal) => {{
        match unsafe { $ptr.as_mut() } {
            Some(handle) => handle,
            None => {
                return FfiResult::err(ffi_error_invalid_input(concat!(
                    $label,
                    " handle is null"
                )))
            }
        }
    }};
}

macro_rules! ffi_borrow {
    ($ptr:expr, $label:literal, $ty:ty) => {{
        let handle = ffi_require_handle!($ptr, $label);
        match borrow_handle::<$ty>(handle.ptr, $label) {
            Ok(value) => value,
            Err(message) => return FfiResult::err(message),
        }
    }};
}

macro_rules! ffi_borrow_mut {
    ($ptr:expr, $label:literal, $ty:ty) => {{
        let handle = ffi_require_handle!($ptr, $label);
        match borrow_handle_mut::<$ty>(handle.ptr, $label) {
            Ok(value) => value,
            Err(message) => return FfiResult::err(message),
        }
    }};
}

macro_rules! ffi_required_string {
    ($ptr:expr, $label:literal) => {{
        match required_string($ptr, $label) {
            Ok(value) => value,
            Err(message) => return FfiResult::err(message),
        }
    }};
}

macro_rules! ffi_handle_free {
    ($ptr:expr, $ty:ty) => {{
        if let Some(handle) = unsafe { $ptr.as_mut() } {
            if !handle.ptr.is_null() {
                unsafe { drop(Box::from_raw(handle.ptr as *mut $ty)) };
                handle.ptr = std::ptr::null_mut();
            }
        }
    }};
}

macro_rules! ffi_handle_getter {
    ($name:ident, $ffi_ty:ty, $inner_ty:ty, $label:literal, $ret:ty, |$arg:ident| $body:expr) => {
        #[unsafe(no_mangle)]
        /// # Safety
        /// Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
        pub unsafe extern "C" fn $name(handle: *mut $ffi_ty) -> FfiResult<$ret> {
            let value = ffi_borrow!(handle, $label, $inner_ty);
            let $arg: &$inner_ty = value;
            FfiResult::ok({ $body })
        }
    };
}

macro_rules! ffi_take_handle {
    ($ptr:expr, $label:literal, $ty:ty) => {{
        if $ptr.is_null() {
            return FfiResult::err(ffi_error_invalid_input(concat!(
                $label,
                " handle is null"
            )));
        }
        let handle = unsafe { &mut *$ptr };
        match take_handle::<$ty>(&mut handle.ptr, $label) {
            Ok(value) => value,
            Err(message) => return FfiResult::err(message),
        }
    }};
}
//! FFI helper macros to keep ABI functions consistent and boilerplate-light.
//!
//! Usage:
//! - Use `ffi_borrow!`/`ffi_borrow_mut!` for handle access.
//! - Use `ffi_required_string!` for required `*const c_char` arguments.
//! - Use `ffi_handle_getter!` for getters that return `FfiResult<T>`.
//! - Use `ffi_take_handle!` for consuming handles (e.g. builder build).
//! - Use `ffi_handle_free!` for free functions.
//!
//! This keeps all FFI null checks and error mapping uniform.
