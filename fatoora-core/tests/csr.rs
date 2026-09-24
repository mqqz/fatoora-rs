use base64ct::{Base64, Encoding};
use fatoora_core::config::EnvironmentType;
use fatoora_core::csr::{CsrError, CsrProperties, SigningKey};
use std::path::Path;
use std::str::FromStr;

#[test]
fn test_parse_csr_config() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_config = CsrProperties::parse_csr_config_file(&config_path).unwrap();
    let env = EnvironmentType::from_str("non_production")
        .map_err(|e| CsrError::Validation {
            message: e.to_string(),
        })
        .unwrap();
    let key = SigningKey::generate();
    let csr = csr_config.build(&key, env).unwrap();
    let subject_str = csr.subject_string();
    assert!(subject_str.contains("C=SA"));
    assert!(subject_str.contains("OU=Riyadh Branch"));
    assert!(subject_str.contains("O=Maximum Speed Tech Supply LTD"));
    assert!(subject_str.contains("CN=TST-"));
}

#[test]
fn test_generate_csr() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_props = std::fs::read_to_string(&config_path).unwrap();
    let csr_config = CsrProperties::from_properties_str(&csr_props).unwrap();

    let env = EnvironmentType::from_str("non_production")
        .map_err(|e| CsrError::Validation {
            message: e.to_string(),
        })
        .unwrap();
    let key = SigningKey::generate();
    let csr = csr_config.build(&key, env).unwrap();

    let der = csr.to_der().unwrap();
    assert!(!der.is_empty(), "CSR DER must not be empty");

    let b64 = Base64::encode_string(&der);
    assert!(!b64.is_empty(), "CSR Base64 must not be empty");

    let exts = csr.extension_values_der();

    let mut found_san = false;
    let mut found_template = false;

    const SAN_OID_DER: &[u8] = b"\x06\x03\x55\x1D\x11";
    const TEMPLATE_OID_DER: &[u8] = b"\x2b\x06\x01\x04\x01\x82\x37\x14\x02";

    for encoded in exts {
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

    let subject_str = csr.subject_string();
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
fn config_file_errors_keep_the_source_path_and_line() {
    use fatoora_core::{Error, ErrorKind};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("device.properties");
    for (contents, kind, expected_type) in [
        (None, ErrorKind::Io, "io"),
        (
            Some("csr.common.name=device\n"),
            ErrorKind::InvalidInput,
            "missing_property",
        ),
        (
            Some("# first line\ncsr.common.name=\\uZZZZ\n"),
            ErrorKind::Parse,
            "properties_parse",
        ),
    ] {
        if let Some(contents) = contents {
            std::fs::write(&path, contents.as_bytes()).unwrap();
        }
        let error: Error = CsrProperties::parse_csr_config_file(&path)
            .unwrap_err()
            .into();
        assert_eq!(error.kind(), kind);
        let details: serde_json::Value = serde_json::from_str(&error.details_json()).unwrap();
        assert_eq!(details["type"], expected_type);
        assert_eq!(details["path"], path.to_str().unwrap());
        if expected_type == "properties_parse" {
            assert_eq!(details["diagnostics"][0]["line"], 2);
        }
        if expected_type == "missing_property" {
            assert_eq!(details["key"], "csr.serial.number");
        }
    }
}

#[test]
fn invalid_csr_fields_are_rejected_before_key_use() {
    let source = include_str!("fixtures/csr-configs/csr-config-example-EN.properties");
    for (key, value) in [
        ("csr.common.name", ""),
        ("csr.common.name", "device!"),
        ("csr.country.name", "SAU"),
        ("csr.invoice.type", "100"),
        ("csr.invoice.type", "1020"),
    ] {
        let properties = source
            .lines()
            .map(|line| {
                if line.starts_with(&format!("{key}=")) {
                    format!("{key}={value}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let error: fatoora_core::Error = CsrProperties::from_properties_str(&properties)
            .unwrap_err()
            .into();
        assert_eq!(error.kind(), fatoora_core::ErrorKind::Validation);
        let details: serde_json::Value = serde_json::from_str(&error.details_json()).unwrap();
        assert_eq!(details["type"], "csr_validation");
    }
}

#[test]
fn csr_names_preserve_literal_delimiters_in_subject_and_san() {
    use x509_cert::{
        der::Decode,
        ext::{
            Extensions,
            pkix::{SubjectAltName, name::GeneralName},
        },
        request::CertReq,
    };
    let key = SigningKey::from_der(include_bytes!(
        "fixtures/sdk-parity/credentials/private-key.der"
    ))
    .unwrap();
    for value in [
        "device,CN=injected",
        "device+CN=injected",
        "branch;OU=other",
        r"device\name",
        " شركة الرياض ",
    ] {
        let properties = CsrProperties::new(
            value.into(),
            "1-TST|2-TST|3-123".into(),
            "399999999900003".into(),
            "Branch".into(),
            "Company".into(),
            "SA".into(),
            "1100".into(),
            value.into(),
            "Supply".into(),
        )
        .unwrap();
        let csr = properties
            .build(&key, EnvironmentType::NonProduction)
            .unwrap();
        let parsed = CertReq::from_der(&csr.to_der().unwrap()).unwrap();
        let subject = &parsed.info.subject;
        assert_eq!(
            subject.iter().count(),
            4,
            "subject attributes changed for {value:?}"
        );
        let cn: Vec<_> = subject
            .iter()
            .filter(|attr| attr.oid.to_string() == "2.5.4.3")
            .collect();
        assert_eq!(cn.len(), 1);
        assert_eq!(cn[0].value.value(), value.as_bytes());
        let extensions = csr
            .extension_values_der()
            .into_iter()
            .flat_map(|der| Extensions::from_der(&der).unwrap())
            .collect::<Vec<_>>();
        let san = extensions
            .iter()
            .find(|ext| ext.extn_id.to_string() == "2.5.29.17")
            .unwrap();
        let names = SubjectAltName::from_der(san.extn_value.as_bytes()).unwrap();
        let GeneralName::DirectoryName(name) = &names.0[0] else {
            panic!("expected directory SAN")
        };
        assert_eq!(
            name.iter().count(),
            5,
            "SAN attributes changed for {value:?}"
        );
        let address = name
            .iter()
            .find(|attr| attr.oid.to_string() == "2.5.4.26")
            .unwrap();
        assert_eq!(address.value.value(), value.as_bytes());
    }
}
