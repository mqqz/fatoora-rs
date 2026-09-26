#![no_main]

use fatoora_core::invoice::sign::{InvoiceSigner, invoice_hash_base64_from_xml_str};
use libfuzzer_sys::fuzz_target;

const CERT: &[u8] = include_bytes!("../seeds/signing_inputs/certificate-der")
    .split_at(1)
    .1;
const KEY: &[u8] = include_bytes!("../seeds/signing_inputs/key-der")
    .split_at(1)
    .1;
const XML: &str = include_str!("../seeds/xml_parse/signed.xml");

fn check_signature(signer: &InvoiceSigner, xml: &str) {
    if let Ok(signed) = signer.sign_xml(xml) {
        // Adding signature/QR nodes must not change the signed invoice digest.
        assert_eq!(
            invoice_hash_base64_from_xml_str(xml).unwrap(),
            invoice_hash_base64_from_xml_str(&signed).unwrap()
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, payload)) = data.split_first() else {
        return;
    };
    match mode % 5 {
        0 => {
            let Ok(xml) = std::str::from_utf8(payload) else {
                return;
            };
            let signer = InvoiceSigner::from_der(CERT, KEY).unwrap();
            check_signature(&signer, xml);
            // A rejected input must not poison subsequent use of the signer.
            signer.sign_xml(XML).expect("signer remains usable");
        }
        1 | 2 => {
            let result = if mode % 5 == 1 {
                InvoiceSigner::from_der(payload, KEY)
            } else {
                InvoiceSigner::from_der(CERT, payload)
            };
            if let Ok(signer) = result {
                let cert = signer.certificate_der().unwrap();
                assert_eq!(cert, if mode % 5 == 1 { payload } else { CERT });
                check_signature(&signer, XML);
            }
        }
        3 | 4 => {
            let Ok(text) = std::str::from_utf8(payload) else {
                return;
            };
            let cert_pem = &include_str!("../seeds/signing_inputs/certificate-pem")[1..];
            let key_pem = &include_str!("../seeds/signing_inputs/key-pem")[1..];
            let result = if mode % 5 == 3 {
                InvoiceSigner::from_pem(text, key_pem)
            } else {
                InvoiceSigner::from_pem(cert_pem, text)
            };
            if let Ok(signer) = result {
                check_signature(&signer, XML);
            }
        }
        _ => unreachable!(),
    }
});
