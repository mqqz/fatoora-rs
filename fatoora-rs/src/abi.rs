use crate::FATOORA_VERSION;
use ffi_support::{FfiStr, rust_string_to_c};

use std::os::raw::c_char;

#[unsafe(no_mangle)]
pub extern "C" fn fatoora_generate_csid(config: FfiStr) -> *mut c_char {
    let cfg = config.as_str();

    let csr = crate::csr::generate_csr_from_config(cfg,
    None, None, false
    ).unwrap_or_else(|_| "ERROR".to_string());

    rust_string_to_c(csr)
}

#[unsafe(no_mangle)]
pub extern "C" fn fatoora_generate_invoice_hash(xml: FfiStr) -> *mut c_char {
    let xml = xml.as_str();

    let hash = crate::sign::generate_hash(xml).unwrap_or_else(|_| "ERROR".to_string());

    rust_string_to_c(hash)
}
