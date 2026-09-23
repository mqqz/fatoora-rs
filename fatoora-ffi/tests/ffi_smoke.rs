use diplomat_runtime::DiplomatWrite;
use fatoora_ffi::common::ffi::BindingError;
use fatoora_ffi::crypto::ffi::{Config, Csr, CsrProperties, Signer, SigningKey};
use fatoora_ffi::invoice::ffi::{FinalizedInvoice, SignedInvoice, Xml};

const INVOICE: &[u8] =
    include_bytes!("../../fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml");
const CERT: &[u8] =
    include_bytes!("../../fatoora-core/tests/fixtures/sdk-parity/credentials/certificate.der");
const KEY: &[u8] =
    include_bytes!("../../fatoora-core/tests/fixtures/sdk-parity/credentials/private-key.der");

fn ok<T>(result: Result<T, Box<BindingError>>) -> T {
    result.unwrap_or_else(|e| {
        panic!(
            "binding error {}: {}",
            e.code(),
            written(|out| e.message(out))
        )
    })
}

#[test]
fn signing_consumes_finalized_and_preserves_signed_xml_exactly() {
    let signer = ok(Signer::from_der(CERT, KEY));
    let mut invoice = ok(FinalizedInvoice::from_xml(INVOICE));
    let data_before = ok(invoice.data());
    let unsigned_hash = written(|out| ok(invoice.hash_base64(out)));
    let mut signed = ok(signer.sign(&mut invoice));
    assert!(invoice.data().is_err());
    assert!(invoice.totals().is_err());
    assert!(signer.sign(&mut invoice).is_err());
    assert_eq!(written(|out| ok(data_before.id(out))), "SME00010");
    let xml = written(|out| ok(signed.xml(out)));
    assert_eq!(written(|out| ok(signed.hash_base64(out))), unsigned_hash);
    assert!(!written(|out| ok(signed.signature(out))).is_empty());
    assert!(!written(|out| ok(signed.qr_code(out))).is_empty());
    let parsed = ok(SignedInvoice::from_xml(xml.as_bytes()));
    assert_eq!(written(|out| ok(parsed.xml(out))), xml);
    assert_eq!(written(|out| ok(signed.into_xml(out))), xml);
    assert!(signed.data().is_err());
    written(|out| assert!(signed.xml(out).is_err()));
    written(|out| assert!(signed.into_xml(out).is_err()));
}

#[test]
fn failed_signing_also_consumes_finalized_invoice() {
    // X.509 BIT STRING permits unused bits; invoice signing requires a byte-aligned
    // certificate signature. Change just that field to exercise a real signing error.
    fn tlv(bytes: &[u8], offset: usize) -> (usize, usize) {
        let first = bytes[offset + 1];
        if first < 128 {
            (offset + 2, usize::from(first))
        } else {
            let count = usize::from(first & 127);
            let length = bytes[offset + 2..offset + 2 + count]
                .iter()
                .fold(0usize, |n, byte| (n << 8) | usize::from(*byte));
            (offset + 2 + count, length)
        }
    }
    let mut cert = CERT.to_vec();
    let (sequence, _) = tlv(&cert, 0);
    let (tbs, tbs_len) = tlv(&cert, sequence);
    let (algorithm, algorithm_len) = tlv(&cert, tbs + tbs_len);
    let signature_tag = algorithm + algorithm_len;
    assert_eq!(cert[signature_tag], 3);
    let (signature, signature_len) = tlv(&cert, signature_tag);
    assert_eq!(cert[signature], 0);
    cert[signature] = 1;
    cert[signature + signature_len - 1] &= 0xfe;
    let signer = ok(Signer::from_der(&cert, KEY));
    let mut invoice = ok(FinalizedInvoice::from_xml(INVOICE));
    let error = signer
        .sign(&mut invoice)
        .err()
        .expect("unaligned signature must fail");
    assert!(written(|out| error.message(out)).contains("not byte-aligned"));
    assert!(invoice.data().is_err());
    written(|out| assert!(invoice.xml(out).is_err()));
    assert_eq!(signer.sign(&mut invoice).err().unwrap().code(), 1);
}

#[test]
fn imported_signed_xml_retains_whitespace_and_declaration() {
    // The fixed fixture is an independent document, not serialized by these bindings.
    let source = std::str::from_utf8(INVOICE).unwrap();
    let mut invoice = ok(SignedInvoice::from_xml(INVOICE));
    assert_eq!(written(|out| ok(invoice.xml(out))), source);
    assert_eq!(written(|out| ok(invoice.into_xml(out))), source);
}

#[test]
fn file_parsing_and_validation_errors_remain_structured() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml");
    let invoice = ok(FinalizedInvoice::from_file(
        path.to_str().unwrap().as_bytes(),
    ));
    assert_eq!(written(|out| ok(ok(invoice.data()).id(out))), "SME00010");
    assert!(FinalizedInvoice::from_file(b"/no/such/invoice.xml").is_err());
    assert!(FinalizedInvoice::from_file(b"bad\0path").is_err());
    assert!(SignedInvoice::from_xml(b"<nope/>").is_err());
    assert!(FinalizedInvoice::from_xml(&[0xff]).is_err());
    assert!(FinalizedInvoice::from_xml(b"<Invoice/>\0").is_err());
    let config = ok(Config::new(0));
    let error = Xml::validate(&config, b"<Invoice/>").err().unwrap();
    let details: serde_json::Value =
        serde_json::from_str(&written(|out| error.details_json(out))).unwrap();
    assert!(details["type"].is_string());
    assert!(Xml::validate(&config, &[0xff]).is_err());
    written(|out| assert!(Xml::hash(b"<bad\0", out).is_err()));
}

#[test]
fn csr_build_preserves_subject_key_and_owned_extensions() {
    let props = ok(CsrProperties::from_properties_str(include_bytes!(
        "../../fatoora-core/tests/fixtures/csr-configs/csr-config-example-EN.properties"
    )));
    let key = ok(SigningKey::from_der(KEY));
    let csr = ok(props.build(&key, 0));
    assert!(props.build(&key, 255).is_err());
    let der = ok(csr.to_der());
    let parsed = ok(Csr::from_der(der.as_slice()));
    assert_eq!(ok(parsed.to_der()).as_slice(), der.as_slice());
    let subject = written(|out| ok(parsed.subject_string(out)));
    assert!(subject.contains("C=SA"));
    let extensions = ok(parsed.extension_values_der());
    assert!(!extensions.is_empty());
    let first = ok(extensions.get(0));
    assert!(extensions.get(extensions.len()).is_err());
    drop(extensions);
    drop(parsed);
    drop(csr);
    assert!(!first.as_slice().is_empty());
}

#[test]
fn signer_certificate_der_is_exact_and_xml_errors_are_fallible() {
    let signer = ok(Signer::from_der(CERT, KEY));
    assert_eq!(ok(signer.certificate_der()).as_slice(), CERT);
    written(|out| assert!(signer.sign_xml(b"<broken", out).is_err()));
    written(|out| assert!(signer.sign_xml(b"<Invoice/>\0", out).is_err()));
}

fn written(f: impl FnOnce(&mut DiplomatWrite)) -> String {
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
