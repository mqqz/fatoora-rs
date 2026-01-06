use ffi_support::FfiStr;

use std::os::raw::c_char;

#[unsafe(no_mangle)]
pub extern "C" fn fatoora_generate_invoice_hash(_xml: FfiStr) -> *mut c_char {
    todo!()
}
