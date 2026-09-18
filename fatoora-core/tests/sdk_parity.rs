//! Mandatory offline compatibility checks; maintenance capture lives in scripts/sdk_parity.py.
use base64ct::{Base64, Encoding};
use fatoora_core::{
    config::Config,
    invoice::{sign::invoice_hash_base64_from_xml_str, validation::validate_xml_invoice_from_str},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk-parity")
}
fn manifest() -> Value {
    serde_json::from_slice(
        &fs::read(root().join("manifest.json"))
            .expect("required SDK corpus missing; see docs/development/sdk-parity.md"),
    )
    .unwrap()
}

#[test]
fn corpus_integrity_and_required_inventory() {
    let m = manifest();
    assert_eq!(m["schema_version"], 1);
    assert_eq!(m["sdk"]["version"], "238-R3.4.8");
    for (path, expected) in m["artifacts"].as_object().unwrap() {
        let bytes = fs::read(root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            expected.as_str().unwrap(),
            "{path}"
        );
    }
    let cases = m["cases"].as_array().unwrap();
    let ids: std::collections::BTreeSet<_> =
        cases.iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), cases.len(), "duplicate cases");
    let mut required: std::collections::BTreeSet<String> = [
        "simplified-invoice",
        "standard-invoice",
        "standard-credit",
        "standard-debit",
        "simplified-credit",
        "simplified-debit",
        "mixed-vat",
        "prepayment",
        "foreign-currency",
        "export-self-billed",
        "out-of-scope",
        "comments",
        "processing-instruction",
        "arabic",
        "text-whitespace",
        "character-reference",
        "cdata",
        "unused-namespace",
        "included-amount",
        "missing-id",
        "invalid-datatype",
        "wrong-order",
        "wrong-namespace",
        "malformed",
        "excluded-extension",
        "excluded-signature",
        "excluded-qr",
        "crlf",
        "alternate-prefix",
        "explicit-default-namespace",
        "namespace-order",
        "attribute-order-a",
        "attribute-order-b",
        "empty-element-a",
        "empty-element-b",
        "payable-rounding",
        "exempt",
        "zero-rated",
        "document-charge",
        "csr-missing-property",
        "csr-unsupported-value",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for lang in ["en", "ar"] {
        for group in ["individual", "group"] {
            for env in ["production", "simulation", "nonproduction"] {
                required.insert(format!("csr-{lang}-{group}-{env}"));
            }
        }
    }
    assert_eq!(
        ids.iter()
            .map(|s| s.to_string())
            .collect::<std::collections::BTreeSet<_>>(),
        required,
        "required operation inventory changed"
    );
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let input = if kind.starts_with("csr") {
            "csr.properties"
        } else {
            "input.xml"
        };
        let input_path = format!("cases/{id}/{input}");
        assert_eq!(
            case["input_sha256"], m["artifacts"][&input_path],
            "input provenance {id}"
        );
        let required_files: &[&str] = match kind {
            "csr" => &[
                "sdk.csr.der",
                "sdk-key.der",
                "evidence/csr/stdout.txt",
                "evidence/csr/process.json",
            ],
            "csr-invalid" => &[
                "expected.json",
                "evidence/csr/stdout.txt",
                "evidence/csr/process.json",
            ],
            "malformed" => &["expected.json", "evidence/validate/stdout.txt"],
            "invoice" => &[
                "expected.json",
                "canonical.xml",
                "sdk-signed.xml",
                "signed-properties.xml",
                "evidence/hash/stdout.txt",
                "evidence/qr/stdout.txt",
            ],
            "xml" | "invalid" => &["expected.json", "canonical.xml", "evidence/hash/stdout.txt"],
            _ => panic!("unknown case kind {kind}"),
        };
        for file in required_files {
            assert!(
                m["artifacts"].get(format!("cases/{id}/{file}")).is_some(),
                "missing {id}/{file}"
            );
        }
    }
    assert_eq!(m["known_differences"].as_array().unwrap().len(), 1);
    assert_eq!(m["known_differences"][0]["id"], "SDK-QR-001");
    assert_eq!(m["known_differences"][0]["sdk"], "1000.00");
    assert_eq!(m["known_differences"][0]["rust"], "1000.01");
    for id in [
        "simplified-invoice",
        "standard-invoice",
        "standard-credit",
        "standard-debit",
        "simplified-credit",
        "simplified-debit",
        "mixed-vat",
        "prepayment",
        "foreign-currency",
        "export-self-billed",
        "out-of-scope",
    ] {
        let c = cases
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("required case {id} missing"));
        assert_eq!(c["kind"], "invoice");
        for file in [
            "input.xml",
            "canonical.xml",
            "sdk-signed.xml",
            "expected.json",
        ] {
            assert!(
                m["artifacts"].get(format!("cases/{id}/{file}")).is_some(),
                "{id}/{file}"
            );
        }
    }
}

#[test]
fn hashes_canonical_bytes_and_xsd_match_official_sdk() {
    for c in manifest()["cases"].as_array().unwrap() {
        if c["kind"].as_str().unwrap().starts_with("csr") {
            continue;
        }
        let id = c["id"].as_str().unwrap();
        let dir = root().join("cases").join(id);
        let xml = fs::read_to_string(dir.join("input.xml")).unwrap();
        let expected: Value =
            serde_json::from_slice(&fs::read(dir.join("expected.json")).unwrap()).unwrap();
        if let Some(hash) = expected["hash"].as_str() {
            assert_eq!(
                invoice_hash_base64_from_xml_str(&xml).unwrap(),
                hash,
                "hash {id}"
            );
            let canonical = fs::read(dir.join("canonical.xml")).unwrap();
            assert_eq!(
                Base64::encode_string(&Sha256::digest(canonical)),
                hash,
                "SDK canonical hash {id}"
            );
        }
        let result = validate_xml_invoice_from_str(&xml, &Config::default());
        if c["kind"] == "malformed" {
            assert!(
                matches!(
                    result,
                    Err(fatoora_core::invoice::validation::XmlValidationError::XmlParse { .. })
                ),
                "{id}"
            );
            assert_eq!(expected["validation"]["parse"], "failed");
            continue;
        }
        let valid = result.is_ok();
        assert_eq!(valid, expected["validation"]["xsd"] == "passed", "XSD {id}");
    }
}

#[test]
fn csr_characteristics_and_proof_of_possession_match_sdk() {
    use fatoora_core::{
        config::EnvironmentType,
        csr::{CsrProperties, SigningKey},
    };
    use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use x509_cert::{
        der::{Decode, Encode},
        request::CertReq,
    };
    for case in manifest()["cases"].as_array().unwrap() {
        if case["kind"] != "csr" {
            continue;
        }
        let id = case["id"].as_str().unwrap();
        let dir = root().join("cases").join(id);
        let reference = CertReq::from_der(&fs::read(dir.join("sdk.csr.der")).unwrap()).unwrap();
        let key = SigningKey::from_der(&fs::read(dir.join("sdk-key.der")).unwrap()).unwrap();
        let environment = match case["environment"].as_str().unwrap() {
            "production" => EnvironmentType::Production,
            "simulation" => EnvironmentType::Simulation,
            "nonproduction" => EnvironmentType::NonProduction,
            _ => panic!("unknown environment"),
        };
        let properties = CsrProperties::from_properties_str(
            &fs::read_to_string(dir.join("csr.properties")).unwrap(),
        )
        .unwrap();
        let actual = CertReq::from_der(
            &properties
                .build(&key, environment)
                .unwrap()
                .to_der()
                .unwrap(),
        )
        .unwrap();
        for csr in [&reference, &actual] {
            let key = VerifyingKey::from_sec1_bytes(
                csr.info.public_key.subject_public_key.as_bytes().unwrap(),
            )
            .unwrap();
            let signature = Signature::from_der(csr.signature.as_bytes().unwrap()).unwrap();
            key.verify(&csr.info.to_der().unwrap(), &signature.normalize_s())
                .expect(id);
        }
        assert_eq!(
            actual.info.public_key, reference.info.public_key,
            "SPKI {id}"
        );
        assert_eq!(
            actual.algorithm, reference.algorithm,
            "signature algorithm {id}"
        );
        assert_eq!(actual.info.subject, reference.info.subject, "subject {id}");
        assert_eq!(
            actual.info.attributes, reference.info.attributes,
            "extensions {id}"
        );
    }
}

#[test]
fn canonical_mutation_relations_are_explicit() {
    let hash = |id: &str| -> Value {
        serde_json::from_slice::<Value>(
            &fs::read(root().join("cases").join(id).join("expected.json")).unwrap(),
        )
        .unwrap()["hash"]
            .clone()
    };
    let base = hash("simplified-invoice");
    for id in [
        "comments",
        "crlf",
        "character-reference",
        "cdata",
        "namespace-order",
    ] {
        assert_eq!(hash(id), base, "{id}");
    }
    for id in [
        "processing-instruction",
        "text-whitespace",
        "alternate-prefix",
        "included-amount",
    ] {
        assert_ne!(hash(id), base, "{id}");
    }
    assert_eq!(hash("attribute-order-a"), hash("attribute-order-b"));
    assert_eq!(hash("empty-element-a"), hash("empty-element-b"));
}

#[test]
fn csr_rejections_match_explicit_sdk_failures() {
    for id in ["csr-missing-property", "csr-unsupported-value"] {
        let dir = root().join("cases").join(id);
        let properties = fs::read_to_string(dir.join("csr.properties")).unwrap();
        assert!(
            fatoora_core::csr::CsrProperties::from_properties_str(&properties).is_err(),
            "{id}"
        );
        let expected: Value =
            serde_json::from_slice(&fs::read(dir.join("expected.json")).unwrap()).unwrap();
        assert_eq!(expected["result"], "failed");
        let raw = fs::read_to_string(dir.join("evidence/csr/stdout.txt")).unwrap();
        assert_eq!(raw.matches(expected["marker"].as_str().unwrap()).count(), 1);
    }
}

#[test]
fn excluded_subtree_content_does_not_change_hash() {
    for id in ["excluded-extension", "excluded-signature", "excluded-qr"] {
        let dir = root().join("cases").join(id);
        let xml = fs::read_to_string(dir.join("input.xml")).unwrap();
        let changed = xml.replace("excluded", "different excluded content");
        assert_ne!(xml, changed);
        let expected: Value =
            serde_json::from_slice(&fs::read(dir.join("expected.json")).unwrap()).unwrap();
        assert_eq!(
            invoice_hash_base64_from_xml_str(&changed).unwrap(),
            expected["hash"].as_str().unwrap()
        );
    }
}
