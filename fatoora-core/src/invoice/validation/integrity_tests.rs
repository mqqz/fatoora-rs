use super::*;
use std::{fs, path::PathBuf};

const SIMPLIFIED: &str =
    include_str!("../../../tests/fixtures/sdk-parity/cases/simplified-invoice/sdk-signed.xml");
const SEED: &str =
    "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==";

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn violation<T>(result: Checked<T>, expected: &str) {
    match result {
        Err(CheckError::Violation(code, _)) => assert_eq!(code, expected),
        Err(CheckError::Backend(message)) => panic!("unexpected backend failure: {message}"),
        Ok(_) => panic!("expected {expected}, validation succeeded"),
    }
}

fn replace(input: &str, old: &str, new: &str) -> String {
    assert_eq!(
        input.matches(old).count(),
        1,
        "mutation must select one original: {old}"
    );
    input.replacen(old, new, 1)
}

fn text(input: &str, path: &str) -> String {
    Xml::parse(input).unwrap().text(path).unwrap()
}

fn replace_text(input: &str, path: &str, value: &str) -> String {
    replace(input, &text(input, path), value)
}

fn refresh_properties_digest(input: &str) -> String {
    let preimage = integrity_xml::properties_preimage(input).unwrap();
    let digest =
        Base64::encode_string(format!("{:x}", Sha256::digest(preimage.as_bytes())).as_bytes());
    replace_text(
        input,
        "//ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue",
        &digest,
    )
}

fn check_signature(input: &str) -> Checked<Verified> {
    signature(&Xml::parse(input).unwrap(), input)
}

#[test]
fn all_fifteen_frozen_sdk_signatures_verify_and_simplified_qrs_match() {
    let mut signed = 0;
    let mut qrs = 0;
    for entry in fs::read_dir(fixtures().join("sdk-parity/cases")).unwrap() {
        let directory = entry.unwrap().path();
        let path = directory.join("sdk-signed.xml");
        if !path.exists() {
            continue;
        }
        let input = fs::read_to_string(path).unwrap();
        let xml = Xml::parse(&input).unwrap();
        let verified =
            signature(&xml, &input).unwrap_or_else(|e| panic!("{}: {e:?}", directory.display()));
        assert_eq!(decode(&verified.hash, 32, "hash").unwrap().len(), 32);
        signed += 1;
        if directory
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("simplified-")
        {
            qr(&xml, &verified).unwrap_or_else(|e| panic!("{}: {e:?}", directory.display()));
            qrs += 1;
        }
    }
    assert_eq!(signed, 15);
    assert_eq!(qrs, 3);
}

#[test]
fn signature_requires_one_anchored_tree_unique_ids_and_scalar_values() {
    let duplicate = replace(
        SIMPLIFIED,
        "</ext:UBLExtensions>",
        "</ext:UBLExtensions><ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'/>",
    );
    violation(check_signature(&duplicate), "SIGNATURE_STRUCTURE");
    let wrong_namespace = replace(
        SIMPLIFIED,
        "<ds:SignedInfo>",
        "<ds:SignedInfo xmlns:ds='urn:lookalike'>",
    );
    violation(check_signature(&wrong_namespace), "INTEGRITY_STRUCTURE");
    for attribute in ["Id", "ID", "id", "xml:id"] {
        let duplicate = replace(
            SIMPLIFIED,
            "<ds:Object>",
            &format!("<ds:Object {attribute}='signature'>"),
        );
        violation(check_signature(&duplicate), "SIGNATURE_DUPLICATE_ID");
    }
    let value = text(SIMPLIFIED, "//ds:SignatureValue");
    let nested = replace(SIMPLIFIED, &value, &format!("<ds:Part>{value}</ds:Part>"));
    violation(check_signature(&nested), "INTEGRITY_STRUCTURE");
    violation(
        check_signature(&format!("<root xmlns:ds='{DS}'><ds:Signature/></root>")),
        "INTEGRITY_STRUCTURE",
    );
}

#[test]
fn algorithms_transforms_and_references_cannot_redirect_verification() {
    for (old, new, code) in [
        (
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            "urn:untrusted-algorithm",
            "SIGNATURE_ALGORITHM",
        ),
        (
            "URI=\"#xadesSignedProperties\"",
            "URI=\"#missing\"",
            "SIGNATURE_REFERENCES",
        ),
        (
            "Id=\"invoiceSignedData\" URI=\"\"",
            "Id=\"invoiceSignedData\" URI=\"https://example.invalid/invoice\"",
            "SIGNATURE_ALGORITHM",
        ),
        (
            "Target=\"signature\"",
            "Target=\"another\"",
            "SIGNATURE_REFERENCES",
        ),
        (
            "<ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)",
            "<ds:XPath xmlns:ext='urn:wrong'>not(//ancestor-or-self::ext:UBLExtensions)",
            "SIGNATURE_TRANSFORMS",
        ),
        (
            "</ds:SignedInfo>",
            "<ds:Reference URI='#extra'/></ds:SignedInfo>",
            "SIGNATURE_REFERENCES",
        ),
        (
            "Type=\"http://www.w3.org/2000/09/xmldsig#SignatureProperties\" URI=\"#xadesSignedProperties\">",
            "Type=\"http://www.w3.org/2000/09/xmldsig#SignatureProperties\" URI=\"#xadesSignedProperties\"><ds:Transforms/>",
            "SIGNATURE_TRANSFORMS",
        ),
    ] {
        violation(check_signature(&replace(SIMPLIFIED, old, new)), code);
    }
    let algorithm =
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256\"/>";
    let parameter = "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256\"><ds:HMACOutputLength>256</ds:HMACOutputLength></ds:SignatureMethod>";
    violation(
        check_signature(&replace(SIMPLIFIED, algorithm, parameter)),
        "SIGNATURE_ALGORITHM",
    );
    let targeted = replace(SIMPLIFIED, "Target=\"signature\"", "Target=\"#signature\"");
    assert!(check_signature(&targeted).is_ok());
}

#[test]
fn certificate_metadata_remains_bound_after_properties_digest_is_recomputed() {
    for (path, replacement, expected) in [
        (
            "//xades:IssuerSerial/ds:X509IssuerName",
            "CN=Other issuer",
            "SIGNATURE_CERTIFICATE_ISSUER",
        ),
        (
            "//xades:IssuerSerial/ds:X509SerialNumber",
            "1",
            "SIGNATURE_CERTIFICATE_SERIAL",
        ),
        (
            "//xades:IssuerSerial/ds:X509SerialNumber",
            "not-a-number",
            "SIGNATURE_CERTIFICATE_SERIAL",
        ),
        (
            "//xades:CertDigest/ds:DigestValue",
            "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMA==",
            "SIGNATURE_CERTIFICATE_DIGEST",
        ),
    ] {
        let changed = replace_text(SIMPLIFIED, path, replacement);
        violation(check_signature(&changed), "SIGNED_PROPERTIES_DIGEST");
        let changed = refresh_properties_digest(&changed);
        violation(check_signature(&changed), expected);
    }
    let cert = text(SIMPLIFIED, "//ds:X509Certificate");
    let duplicate = replace(
        SIMPLIFIED,
        "</ds:X509Data>",
        &format!("<ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data>"),
    );
    violation(check_signature(&duplicate), "SIGNATURE_CERTIFICATE");
}

#[test]
fn signature_namespace_aliases_preserve_reference_and_certificate_binding() {
    let aliased = SIMPLIFIED
        .replace("ds:", "sigds:")
        .replace("xmlns:ds=", "xmlns:sigds=")
        .replace("xades:", "properties:")
        .replace("xmlns:xades=", "xmlns:properties=");
    let aliased = refresh_properties_digest(&aliased);
    let xml = Xml::parse(&aliased).unwrap();
    let verified = signature(&xml, &aliased).unwrap();
    qr(&xml, &verified).unwrap();
}

fn framed(tags: &[(u8, Vec<u8>)]) -> Vec<u8> {
    tags.iter()
        .flat_map(|(tag, value)| {
            assert!(value.len() <= 255);
            [vec![*tag, value.len() as u8], value.clone()].concat()
        })
        .collect()
}

#[test]
fn tlv_framing_rejects_truncation_duplicates_unknown_and_missing_tags() {
    let tags: Vec<_> = (1..=9).map(|tag| (tag, vec![b'A'])).collect();
    let valid = framed(&tags);
    assert_eq!(qr_tags(&valid).unwrap().len(), 9);
    for bytes in [
        vec![],
        vec![1],
        vec![1, 0],
        vec![1, 2, b'A'],
        vec![0, 1, b'A'],
        vec![10, 1, b'A'],
        valid[..valid.len() - 1].to_vec(),
        framed(&tags[..8]),
        [valid.clone(), vec![1, 1, b'A']].concat(),
    ] {
        violation(qr_tags(&bytes), "QR_TLV");
    }
    let mut reversed = tags.clone();
    reversed.swap(0, 1);
    violation(qr_tags(&framed(&reversed)), "QR_TLV");
    let mut maximum = tags;
    maximum[0].1 = vec![b'A'; 255];
    assert_eq!(qr_tags(&framed(&maximum)).unwrap()[&1].len(), 255);
}

fn qr_with_tag(input: &str, tag: u8, value: &[u8]) -> String {
    let original = text(input, QR);
    let mut tags = qr_tags(&decode(&original, 4096, "QR_BASE64").unwrap()).unwrap();
    tags.insert(tag, value.to_vec());
    let encoded = Base64::encode_string(&framed(&tags.into_iter().collect::<Vec<_>>()));
    replace(input, &original, &encoded)
}

#[test]
fn qr_values_reject_float_collisions_nonfinite_and_malformed_timestamps() {
    for (tag, value, expected) in [
        (5, b"15.00000000000000000001".as_slice(), Some("QR_VAT")),
        (5, b"NaN", Some("QR_VAT")),
        (5, b"15e0", Some("QR_VAT")),
        (5, b"15.0", None),
        (5, b"\xff", Some("QR_VAT")),
        (3, b"2024-01-01T12:30:00ZZ", Some("QR_TIMESTAMP")),
        (3, b"2024-01-01T12:30:00garbage", Some("QR_TIMESTAMP")),
        (3, b"2024-01-01T12:30:00+03:00", Some("QR_TIMESTAMP")),
        (3, b"2024-01-01T15:30:00+03:00", None),
        (3, b"\xff", Some("QR_TIMESTAMP")),
    ] {
        let input = qr_with_tag(SIMPLIFIED, tag, value);
        let xml = Xml::parse(&input).unwrap();
        let verified = signature(&xml, &input).expect("QR bytes are excluded from invoice digest");
        if let Some(code) = expected {
            violation(qr(&xml, &verified), code);
        } else {
            qr(&xml, &verified).unwrap();
        }
    }
}

#[test]
fn base64_and_previous_hash_formats_have_explicit_bounds() {
    assert_eq!(decode(" Y Q==\n", 8, "DECODE").unwrap(), b"a");
    for value in ["YQ", "YQ==\u{a0}", "!!!!", "AAAAAAAA", "AAAAAAAAAAAA"] {
        violation(decode(value, 4, "DECODE"), "DECODE");
    }
    for value in [
        SEED.to_owned(),
        Base64::encode_string(&[0; 32]),
        Base64::encode_string(&[b'a'; 64]),
    ] {
        assert!(valid_previous_hash(&value));
    }
    for value in [
        format!(" {SEED}"),
        format!("{SEED}\n"),
        Base64::encode_string(&[0; 31]),
        Base64::encode_string(&[b'g'; 64]),
        "a".repeat(89),
    ] {
        assert!(!valid_previous_hash(&value));
    }
    let xml = Xml::parse(SIMPLIFIED).unwrap();
    previous_hash(&xml, Some(SEED)).unwrap();
    previous_hash(&xml, None).unwrap();
    violation(
        previous_hash(&xml, Some(&Base64::encode_string(&[0; 32]))),
        "PIH_MISMATCH",
    );
}

#[test]
fn frozen_official_sdk_integrity_mutations_match_declared_native_policy() {
    let corpus = fixtures().join("business-rules/integrity");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(corpus.join("manifest.json")).expect("frozen integrity manifest"),
    )
    .unwrap();
    assert_eq!(manifest["sdk_version"], "238-R3.4.8");
    assert_eq!(
        manifest["jar_sha256"],
        "48abeb828d453ef6fafba792fddbbb2701da5c7018c24bde918853e80ff5d530"
    );
    for (relative, digest) in manifest["artifacts"].as_object().unwrap() {
        let bytes = fs::read(corpus.join(relative)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            digest.as_str().unwrap(),
            "{relative}"
        );
    }
    let cases = manifest["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 40);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let input = fs::read_to_string(corpus.join("cases").join(id).join("input.xml")).unwrap();
        let xml = Xml::parse(&input).unwrap();
        let targets = case["native"].as_object().unwrap();
        if targets.is_empty() {
            let verified = signature(&xml, &input).unwrap_or_else(|e| panic!("{id}: {e:?}"));
            if id.starts_with("simplified-") {
                qr(&xml, &verified).unwrap_or_else(|e| panic!("{id}: {e:?}"));
            }
            previous_hash(&xml, Some(SEED)).unwrap();
        }
        for (stage, expected) in targets {
            let result = match stage.as_str() {
                "signature" => signature(&xml, &input).map(|_| ()),
                "qr" => {
                    let verified =
                        signature(&xml, &input).unwrap_or_else(|e| panic!("{id}: {e:?}"));
                    qr(&xml, &verified)
                }
                "previous_invoice_hash" => previous_hash(&xml, Some(SEED)),
                _ => panic!("unknown frozen stage: {stage}"),
            };
            match expected.as_str() {
                Some(code) => match result {
                    Err(CheckError::Violation(actual, _)) => assert_eq!(actual, code, "{id}"),
                    Err(CheckError::Backend(message)) => {
                        panic!("{id}: unexpected execution failure: {message}")
                    }
                    Ok(()) => panic!("{id}: expected {code}"),
                },
                None => {
                    assert!(expected.is_null(), "{id}: invalid native expectation");
                    result.unwrap_or_else(|e| panic!("{id}: {e:?}"));
                }
            }
        }
    }
}
