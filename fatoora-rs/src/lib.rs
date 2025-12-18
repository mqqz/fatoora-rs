pub mod abi;
pub mod api_request;
pub mod config;
pub mod csr;
pub mod invoice;
pub mod qr;
pub mod sign;

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
