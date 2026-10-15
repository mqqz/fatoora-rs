//! Host integration for the Diplomat WASM artifact.
#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn fatoora_random_fill(ptr: *mut u8, len: usize) -> i32;
}

// getrandom's custom backend is defined once, in the final binding artifact.
// getrandom 0.4 retains the v03 backend symbol used by transitive 0.3 callers.
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    // SAFETY: getrandom provides a writable allocation of len bytes. The loader
    // fills it synchronously, without calling Rust or growing WASM memory.
    if unsafe { fatoora_random_fill(dest, len) } == 0 {
        Ok(())
    } else {
        Err(getrandom::Error::UNSUPPORTED)
    }
}
