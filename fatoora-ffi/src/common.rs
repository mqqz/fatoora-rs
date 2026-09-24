//! Diplomat invoice bindings. Core types remain independent of the binding framework.

struct ErrorData {
    code: i32,
    message: String,
    details: String,
}

pub(crate) fn core_error(error: impl Into<fatoora_core::Error>) -> Box<ffi::BindingError> {
    let error = error.into();
    Box::new(ffi::BindingError(ErrorData {
        code: error.kind() as i32,
        message: error.to_string(),
        details: error.details_json(),
    }))
}

pub(crate) fn context_error(
    error: impl Into<fatoora_core::Error>,
    context: &str,
) -> Box<ffi::BindingError> {
    let mut error = core_error(error);
    error.0.message = format!("{context}: {}", error.0.message);
    error
}
pub(crate) fn local_error(code: i32, message: &str) -> Box<ffi::BindingError> {
    Box::new(ffi::BindingError(ErrorData {
        code,
        message: message.into(),
        details: "{\"type\":\"binding_error\"}".into(),
    }))
}

pub(crate) fn text(bytes: &diplomat_runtime::DiplomatStr) -> Result<&str, Box<ffi::BindingError>> {
    let value =
        std::str::from_utf8(bytes).map_err(|_| local_error(1, "text must be valid UTF-8"))?;
    if value.contains('\0') {
        return Err(local_error(1, "text must not contain NUL"));
    }
    Ok(value)
}
pub(crate) fn optional_text(
    bytes: Option<&diplomat_runtime::DiplomatStr>,
) -> Result<Option<String>, Box<ffi::BindingError>> {
    bytes.map(|v| text(v).map(str::to_owned)).transpose()
}
pub(crate) fn write(
    value: impl AsRef<str>,
    out: &mut diplomat_runtime::DiplomatWrite,
) -> Result<(), Box<ffi::BindingError>> {
    use std::fmt::Write;
    let value = value.as_ref();
    if value.contains('\0') {
        return Err(local_error(1, "text must not contain NUL"));
    }
    out.write_str(value)
        .map_err(|_| local_error(9, "output write failed"))
}
pub(crate) fn environment(
    value: u8,
) -> Result<fatoora_core::config::EnvironmentType, Box<ffi::BindingError>> {
    use fatoora_core::config::EnvironmentType::*;
    match value {
        0 => Ok(NonProduction),
        1 => Ok(Simulation),
        2 => Ok(Production),
        _ => Err(local_error(1, "invalid environment")),
    }
}
pub(crate) fn boundary<T>(
    f: impl FnOnce() -> Result<T, Box<ffi::BindingError>>,
) -> Result<T, Box<ffi::BindingError>> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(payload) => {
            if let Err(nested) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
            {
                std::mem::forget(nested);
            }
            Err(local_error(9, "internal operation panicked"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::boundary;

    #[test]
    fn panic_after_consumption_returns_internal_error() {
        let mut state = Some("owned builder state");
        let error = boundary::<()>(|| {
            let _owned = state.take();
            panic!("operation failed");
        })
        .err()
        .unwrap();
        assert_eq!(error.code(), 9);
        assert!(state.is_none());
    }

    #[test]
    fn panicking_payload_destructor_is_contained() {
        struct Payload;
        impl Drop for Payload {
            fn drop(&mut self) {
                panic!("payload destructor");
            }
        }
        let error = boundary::<()>(|| std::panic::panic_any(Payload))
            .err()
            .unwrap();
        assert_eq!(error.code(), 9);
    }
}

#[diplomat::bridge]
#[diplomat::abi_rename = "fatoora_{0}"]
#[diplomat::attr(cpp, namespace = "fatoora")]
pub mod ffi {
    use super::{ErrorData, boundary, write};
    use std::fmt::Write;
    #[diplomat::opaque]
    pub struct BindingError(pub(super) ErrorData);
    impl BindingError {
        pub fn code(&self) -> i32 {
            self.0.code
        }
        pub fn message(&self, out: &mut diplomat_runtime::DiplomatWrite) {
            let _ = out.write_str(&self.0.message.replace('\0', "\\0"));
        }
        pub fn details_json(&self, out: &mut diplomat_runtime::DiplomatWrite) {
            let _ = out.write_str(&self.0.details);
        }
    }
    #[diplomat::opaque]
    pub struct Text(pub(crate) String);
    impl Text {
        pub fn value(
            &self,
            out: &mut diplomat_runtime::DiplomatWrite,
        ) -> Result<(), Box<BindingError>> {
            boundary(|| write(&self.0, out))
        }
    }
}
