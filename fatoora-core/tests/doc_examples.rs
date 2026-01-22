mod api {
    include!("../examples/api.rs");
}

mod csr {
    include!("../examples/csr.rs");
}

mod invoice_signing {
    include!("../examples/invoice_signing.rs");
}

mod qr {
    include!("../examples/qr.rs");
}

mod validation {
    include!("../examples/validation.rs");
}

#[test]
fn doc_example_api() {
    api::main();
}

#[test]
fn doc_example_csr() {
    csr::main();
}

#[test]
fn doc_example_invoice_signing() {
    invoice_signing::main();
}

#[test]
fn doc_example_qr() {
    qr::main();
}

#[test]
fn doc_example_validation() {
    validation::main();
}
