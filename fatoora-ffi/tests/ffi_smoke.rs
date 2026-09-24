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

#[test]
fn pem_signing_and_exports_preserve_certificate_key_and_signature() {
    use base64ct::{Base64, Encoding};
    use k256::{
        ecdsa::{Signature, VerifyingKey, signature::Verifier},
        pkcs8::DecodePublicKey,
    };
    use x509_cert::{
        Certificate,
        der::{Decode, Encode, EncodePem, pem::LineEnding},
    };
    let certificate = Certificate::from_der(CERT).unwrap();
    let cert_pem = certificate.to_pem(LineEnding::LF).unwrap();
    let key = ok(SigningKey::from_der(KEY));
    let key_pem = written(|out| ok(key.to_pem(out)));
    let restored_key = ok(SigningKey::from_pem(key_pem.as_bytes()));
    assert_eq!(ok(restored_key.to_der()).as_slice(), KEY);
    let signer = ok(Signer::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()));
    drop(restored_key);
    drop(key);
    assert_eq!(written(|out| ok(signer.certificate_pem(out))), cert_pem);
    let xml = written(|out| ok(signer.sign_xml(INVOICE, out)));
    let signed = ok(SignedInvoice::from_xml(xml.as_bytes()));
    let public_key = Base64::decode_vec(&written(|out| ok(signed.public_key(out)))).unwrap();
    assert_eq!(
        public_key,
        certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap()
    );
    let verifying = VerifyingKey::from_public_key_der(&public_key).unwrap();
    let signature = Signature::from_der(
        &Base64::decode_vec(&written(|out| ok(signed.signature(out)))).unwrap(),
    )
    .unwrap();
    let hash = Base64::decode_vec(&written(|out| ok(signed.invoice_hash(out)))).unwrap();
    verifying.verify(&hash, &signature).unwrap();
    let mut tampered = hash;
    tampered[0] ^= 1;
    assert!(verifying.verify(&tampered, &signature).is_err());
    assert_eq!(
        Base64::decode_vec(&written(|out| ok(signed.to_xml_base64(out)))).unwrap(),
        xml.as_bytes()
    );
    assert_eq!(
        written(|out| ok(signed.issuer(out))),
        "CN=PRZEINVOICESCA4-CA, DC=extgazt, DC=gov, DC=local"
    );
    assert_eq!(
        written(|out| ok(signed.signing_time(out))),
        "2025-07-22T15:51:28"
    );
    let cert_signature = ok(signed.zatca_key_signature()).unwrap();
    assert_eq!(
        Base64::decode_vec(&written(|out| ok(cert_signature.value(out)))).unwrap(),
        certificate.signature().as_bytes().unwrap()
    );
}

#[test]
fn csr_binding_encodings_preserve_proof_of_possession_and_environment() {
    use base64ct::{Base64, Encoding};
    use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use x509_cert::{
        der::{Decode, DecodePem, Encode},
        request::CertReq,
    };
    let props = ok(CsrProperties::new(
        b"Device",
        b"1-TST|2-TST|3-123",
        b"399999999900003",
        b"Branch",
        b"Company",
        b"SA",
        b"1100",
        b"Riyadh",
        b"Supply",
    ));
    let key = ok(SigningKey::from_der(KEY));
    for (env, template) in [
        (0, "TSTZATCA-Code-Signing"),
        (1, "PREZATCA-Code-Signing"),
        (2, "ZATCA-Code-Signing"),
    ] {
        let csr = ok(props.build(&key, env));
        let der = ok(csr.to_der());
        let pem = written(|out| ok(csr.to_pem(out)));
        assert_eq!(
            CertReq::from_pem(&pem).unwrap().to_der().unwrap(),
            der.as_slice()
        );
        assert_eq!(
            Base64::decode_vec(&written(|out| ok(csr.to_base64(out)))).unwrap(),
            der.as_slice()
        );
        assert_eq!(
            Base64::decode_vec(&written(|out| ok(csr.to_pem_base64(out)))).unwrap(),
            pem.as_bytes()
        );
        let parsed = CertReq::from_der(der.as_slice()).unwrap();
        assert_eq!(
            std::str::from_utf8(
                parsed
                    .info
                    .subject
                    .iter()
                    .find(|attr| attr.oid.to_string() == "2.5.4.3")
                    .unwrap()
                    .value
                    .value()
            )
            .unwrap(),
            "Device"
        );
        let verifying = VerifyingKey::from_sec1_bytes(
            parsed
                .info
                .public_key
                .subject_public_key
                .as_bytes()
                .unwrap(),
        )
        .unwrap();
        let signature = Signature::from_der(parsed.signature.as_bytes().unwrap()).unwrap();
        verifying
            .verify(&parsed.info.to_der().unwrap(), &signature)
            .unwrap();
        let extensions = ok(csr.extension_values_der());
        let mut templates = Vec::new();
        for i in 0..extensions.len() {
            let bytes = ok(extensions.get(i));
            for ext in x509_cert::ext::Extensions::from_der(bytes.as_slice()).unwrap() {
                if ext.extn_id.to_string() == "1.3.6.1.4.1.311.20.2" {
                    templates.push(
                        x509_cert::der::asn1::Utf8StringRef::from_der(ext.extn_value.as_bytes())
                            .unwrap()
                            .as_str()
                            .to_owned(),
                    );
                }
            }
        }
        assert_eq!(templates, [template]);
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fatoora-core/tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let from_file = ok(CsrProperties::parse_csr_config_file(
        path.to_str().unwrap().as_bytes(),
    ));
    let csr = ok(from_file.build(&key, 0));
    let parsed = CertReq::from_der(ok(csr.to_der()).as_slice()).unwrap();
    assert_eq!(
        std::str::from_utf8(
            parsed
                .info
                .subject
                .iter()
                .find(|attr| attr.oid.to_string() == "2.5.4.3")
                .unwrap()
                .value
                .value()
        )
        .unwrap(),
        "TST-886431145-399999999900003"
    );
}

#[test]
fn signed_file_metadata_and_totals_remain_owned_after_consumption() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml");
    let mut signed = ok(SignedInvoice::from_file(path.to_str().unwrap().as_bytes()));
    let totals = ok(signed.totals());
    assert_eq!(
        written(|out| ok(signed.serial(out))),
        "379112742831380471835263969587287663520528387"
    );
    assert_eq!(
        written(|out| ok(signed.cert_hash(out))),
        "ZDMwMmI0MTE1NzVjOTU2NTk4YzVlODhhYmI0ODU2NDUyNTU2YTVhYjhhMDFmN2FjYjk1YTA2OWQ0NjY2MjQ4NQ=="
    );
    assert_eq!(
        written(|out| ok(signed.signed_props_hash(out))),
        "ZmMwY2ZhNDljNzNjZDA5NmY4NDM4MmY1ZmY1YTA0NjY3MzY4NzMxOGJhYmZmNWU1OGYzZWJlODI3ZDgyZGVkZA=="
    );
    assert_eq!(written(|out| ok(ok(signed.data()).id(out))), "SME00010");
    written(|out| ok(signed.into_xml(out)));
    assert!(signed.totals().is_err());
    drop(signed);
    assert_eq!(written(|out| ok(totals.prepaid_amount(out))), "0");
    assert_eq!(written(|out| ok(totals.payable_rounding_amount(out))), "0");
    assert_eq!(written(|out| ok(totals.payable_amount(out))), "231.15");
    assert_eq!(
        SignedInvoice::from_file(b"/missing/invoice.xml")
            .err()
            .unwrap()
            .code(),
        6
    );
}
