use diplomat_runtime::DiplomatWrite;

pub fn written(f: impl FnOnce(&mut DiplomatWrite)) -> String {
    struct Writer(*mut DiplomatWrite);
    impl Drop for Writer {
        fn drop(&mut self) {
            unsafe {
                diplomat_runtime::diplomat_buffer_write_destroy(self.0);
            }
        }
    }
    let out = Writer(diplomat_runtime::diplomat_buffer_write_create(0));
    unsafe {
        f(&mut *out.0);
        std::str::from_utf8((*out.0).as_bytes()).unwrap().to_owned()
    }
}
