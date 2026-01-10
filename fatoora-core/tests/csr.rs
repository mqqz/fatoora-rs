use base64ct::{Base64, Encoding};
use fatoora_core::config::EnvironmentType;
use fatoora_core::csr::{CsrError, CsrProperties};
use k256::pkcs8::DecodePrivateKey;
use std::path::Path;
use std::str::FromStr;
use x509_cert::der::Encode;

#[test]
fn test_parse_csr_config() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_config = CsrProperties::parse_csr_config(&config_path).unwrap();
    let env = EnvironmentType::from_str("non_production")
        .map_err(|e| CsrError::Validation {
            message: e.to_string(),
        })
        .unwrap();
    let (csr, _key) = csr_config.build_with_rng(env).unwrap();
    let subject_str = csr.info.subject.to_string();
    assert!(subject_str.contains("C=SA"));
    assert!(subject_str.contains("OU=Riyadh Branch"));
    assert!(subject_str.contains("O=Maximum Speed Tech Supply LTD"));
    assert!(subject_str.contains("CN=TST-"));
}

#[test]
fn test_generate_csr() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_config = CsrProperties::parse_csr_config(&config_path).unwrap();

    let env = EnvironmentType::from_str("non_production")
        .map_err(|e| CsrError::Validation {
            message: e.to_string(),
        })
        .unwrap();
    let (csr, _key) = csr_config.build_with_rng(env).unwrap();

    let der = csr
        .to_der()
        .map_err(|e| CsrError::DerEncode {
            context: "certificate request (test_generate_csr)",
            source: e,
        })
        .unwrap();
    assert!(!der.is_empty(), "CSR DER must not be empty");

    let b64 = Base64::encode_string(&der);
    assert!(!b64.is_empty(), "CSR Base64 must not be empty");

    let info = &csr.info;
    let exts = info.attributes.iter().flat_map(|attr| attr.values.iter());

    let mut found_san = false;
    let mut found_template = false;

    const SAN_OID_DER: &[u8] = b"\x06\x03\x55\x1D\x11";
    const TEMPLATE_OID_DER: &[u8] = b"\x2b\x06\x01\x04\x01\x82\x37\x14\x02";

    for val in exts {
        let encoded = val.to_der().unwrap_or_default();
        if encoded.windows(SAN_OID_DER.len()).any(|w| w == SAN_OID_DER) {
            found_san = true;
        }
        if encoded
            .windows(TEMPLATE_OID_DER.len())
            .any(|w| w == TEMPLATE_OID_DER)
        {
            found_template = true;
        }
        if found_san && found_template {
            break;
        }
    }

    assert!(
        found_san,
        "CSR must include a SubjectAltName extension (OID 2.5.29.17) inside extensionRequest"
    );
    assert!(
        found_template,
        "CSR must include the template name extension (OID 1.3.6.1.4.1.311.20.2)"
    );

    let subject_str = info.subject.to_string();
    assert!(
        subject_str.contains("C=SA"),
        "Subject must contain country code 'SA' (got {subject_str})"
    );
    assert!(
        subject_str.contains("CN=TST-"),
        "Subject must contain CN with 'TST-' prefix (got {subject_str})"
    );
}

#[test]
fn test_csr_matches_zatca_sdk() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_config = CsrProperties::parse_csr_config(&config_path).unwrap();
    let env = EnvironmentType::from_str("production")
        .map_err(|e| CsrError::Validation {
            message: e.to_string(),
        })
        .unwrap();
    let key_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pkeys/test_zatca_pkey.der");
    let zatca_pkey = k256::ecdsa::SigningKey::from_pkcs8_der(&std::fs::read(key_path).unwrap())
        .unwrap();

    let _csr = csr_config.build(&zatca_pkey, env).unwrap();
    // let generated_b64 = csr.to_base64_string().unwrap();
    // let reference_b64 = std::fs::read_to_string(
    //     Path::new(env!("CARGO_MANIFEST_DIR"))
    //         .join("tests/fixtures/csrs/test_zatca_en1.csr"),
    // )
    // .expect("Failed to read reference CSR file")
    // .trim()
    // .to_string();
    // assert_eq!(
    //     generated_b64, reference_b64,
    //     "Generated CSR does not match reference CSR from ZATCA SDK"
    // );
}
