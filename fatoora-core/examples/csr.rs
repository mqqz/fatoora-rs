// --8<-- [start:example]
pub fn main() {
    use fatoora_core::config::EnvironmentType;
    use fatoora_core::csr::{CsrProperties, SigningKey};

    let csr_props_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_props = std::fs::read_to_string(&csr_props_path).expect("read csr props");
    let props = CsrProperties::from_properties_str(&csr_props).expect("parse csr props");
    let key = SigningKey::generate();
    let csr = props
        .build(&key, EnvironmentType::NonProduction)
        .expect("build csr");

    let csr_pem = csr.to_pem().expect("csr pem");
    let key_pem = key.to_pem().expect("key pem");
    let csr_b64 = csr.to_base64().expect("csr base64");
    assert!(!csr_b64.is_empty());
    assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    let _ = csr_pem;
}
// --8<-- [end:example]
