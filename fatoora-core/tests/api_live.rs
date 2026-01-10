mod common;

#[cfg(not(feature = "disable-network"))]
use base64ct::{Base64, Encoding};
#[cfg(not(feature = "disable-network"))]
use fatoora_core::api::ZatcaClient;
#[cfg(not(feature = "disable-network"))]
use fatoora_core::config::{Config, EnvironmentType};
#[cfg(not(feature = "disable-network"))]
use fatoora_core::csr::CsrProperties;
#[cfg(not(feature = "disable-network"))]
use std::path::Path;
#[cfg(not(feature = "disable-network"))]
use x509_cert::der::Decode;
#[cfg(not(feature = "disable-network"))]
use x509_cert::request::CertReq;

#[cfg(not(feature = "disable-network"))]
#[tokio::test]
async fn post_compliance_csid_sandbox() {
    let otp = "123345";
    let csr_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/csrs/test_zatca_en1.csr");
    let csr_b64 = std::fs::read_to_string(csr_path).expect("read CSR");
    let csr_der = Base64::decode_vec(csr_b64.trim()).expect("decode CSR base64");
    let csr = CertReq::from_der(&csr_der).expect("parse CSR");

    let client = ZatcaClient::new(Config::default()).expect("client builds");

    let response = client
        .post_csr_for_ccsid(&csr, otp)
        .await
        .expect("CSID request succeeds");
    assert!(
        !response.binary_security_token.is_empty(),
        "empty binary_security_token. response: {:?}",
        response
    );
    assert!(
        !response.secret.is_empty(),
        "empty secret. response: {:?}",
        response
    );
}

#[cfg(feature = "disable-network")]
#[test]
#[ignore = "network tests disabled; enable by omitting --features disable-network"]
fn post_compliance_csid_sandbox() {}

#[cfg(not(feature = "disable-network"))]
#[tokio::test]
async fn post_production_csid_sandbox() {
    let otp = "123345";
    let csr_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/csrs/test_zatca_en1.csr");
    let csr_b64 = std::fs::read_to_string(csr_path).expect("read CSR");
    let csr_der = Base64::decode_vec(csr_b64.trim()).expect("decode CSR base64");
    let csr = CertReq::from_der(&csr_der).expect("parse CSR");
    let client = ZatcaClient::new(Config::default()).expect("client builds");
    let compliance_response = client
        .post_csr_for_ccsid(&csr, otp)
        .await
        .expect("CSID request succeeds");
    println!("Compliance CSID Response: {:?}", compliance_response);
    let production_response = client
        .post_ccsid_for_pcsid(&compliance_response)
        .await
        .expect("Production CSID request succeeds");
    println!("Production CSID Response: {:?}", production_response);
    assert!(
        !production_response.binary_security_token.is_empty(),
        "empty binary_security_token. response: {:?}",
        production_response
    );
    assert!(
        !production_response.secret.is_empty(),
        "empty secret. response: {:?}",
        production_response
    );
}

#[cfg(feature = "disable-network")]
#[test]
#[ignore = "network tests disabled; enable by omitting --features disable-network"]
fn report_simplified_invoice_sandbox() {}

#[cfg(not(feature = "disable-network"))]
#[tokio::test]
async fn check_compliance_with_live_ccsid() {
    let otp = "123345";
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_config = CsrProperties::parse_csr_config(&config_path).expect("csr config");
    let (csr, signer_key) = csr_config
        .build_with_rng(EnvironmentType::NonProduction)
        .expect("csr build");
    let client = ZatcaClient::new(Config::default()).expect("client");
    let ccsid_response = client
        .post_csr_for_ccsid(&csr, otp)
        .await
        .expect("csid response");

    let signer = common::signer_from_csid(&ccsid_response.binary_security_token, &signer_key);
    let signed_invoice = common::dummy_finalized_invoice()
        .sign(&signer)
        .expect("sign invoice with live csid");
    let compliance_response = client
        .check_invoice_compliance(&signed_invoice, &ccsid_response)
        .await
        .expect("report signed invoice");
    assert_eq!(
        compliance_response.reporting_status.unwrap(),
        "REPORTED",
        "invoice not reported successfully"
    );
}

#[cfg(feature = "disable-network")]
#[test]
#[ignore = "network tests disabled; enable by omitting --features disable-network"]
fn check_compliance_with_live_ccsid() {}

#[cfg(not(feature = "disable-network"))]
#[tokio::test]
async fn report_invoice_with_live_pcsid() {
    // csr generation
    use k256::pkcs8::DecodePrivateKey;

    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_config = CsrProperties::parse_csr_config(&config_path).expect("csr config");

    let key_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pkeys/test_zatca_pkey.der");
    let zatca_pkey =
        k256::ecdsa::SigningKey::from_pkcs8_der(&std::fs::read(key_path).unwrap()).unwrap();
    let csr = csr_config
        .build(&zatca_pkey, EnvironmentType::NonProduction)
        .unwrap();

    // now we obtain the ccsids
    let otp = "123345";
    let client = ZatcaClient::new(Config::default()).expect("client");
    let ccsid_response = client
        .post_csr_for_ccsid(&csr, otp)
        .await
        .expect("csid response");

    let signer = common::signer_from_csid(&ccsid_response.binary_security_token, &zatca_pkey);
    let signed_invoice = common::dummy_finalized_invoice()
        .sign(&signer)
        .expect("sign invoice with live csid");

    let compliance_response = client
        .check_invoice_compliance(&signed_invoice, &ccsid_response)
        .await
        .expect("report signed invoice");
    assert_eq!(
        compliance_response.reporting_status.unwrap(),
        "REPORTED",
        "Compliance check failed!"
    );
    let pcsid_response = client
        .post_ccsid_for_pcsid(&ccsid_response)
        .await
        .expect("csid response");
    let signer = common::signer_from_csid(&pcsid_response.binary_security_token, &zatca_pkey);
    let signed_invoice = common::dummy_finalized_invoice()
        .sign(&signer)
        .expect("sign invoice with live csid");

    let reporting_response = client
        .report_simplified_invoice(&signed_invoice, &pcsid_response, false, None)
        .await
        .expect("report signed invoice");
    println!(
        "Invoice reporting errors: {:#?}",
        reporting_response.validation_results
    );
    assert_eq!(
        reporting_response.reporting_status.unwrap(),
        "REPORTED",
        "invoice not reported successfully"
    );
}

#[cfg(feature = "disable-network")]
#[test]
#[ignore = "network tests disabled; enable by omitting --features disable-network"]
fn report_invoice_with_live_pcsid() {}

#[cfg(not(feature = "disable-network"))]
#[tokio::test]
async fn renew_csid_returns_request_id() {
    use k256::pkcs8::DecodePrivateKey;

    let otp = "123456";
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_config = CsrProperties::parse_csr_config(&config_path).expect("csr config");

    let key_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pkeys/test_zatca_pkey.der");
    let zatca_pkey =
        k256::ecdsa::SigningKey::from_pkcs8_der(&std::fs::read(key_path).unwrap()).unwrap();
    let csr = csr_config
        .build(&zatca_pkey, EnvironmentType::NonProduction)
        .unwrap();
    let client = ZatcaClient::new(Config::default()).expect("client");

    let ccsid_response = client
        .post_csr_for_ccsid(&csr, otp)
        .await
        .expect("csid response");
    let pcsid_response = client
        .post_ccsid_for_pcsid(&ccsid_response)
        .await
        .expect("pcsid response");

    let response = client
        .renew_csid(&pcsid_response, &csr, otp, None)
        .await
        .expect("renew csid succeeds");
    assert!(
        response.request_id.is_some(),
        "missing request_id. response: {:?}",
        response
    );
}

#[cfg(feature = "disable-network")]
#[test]
#[ignore = "network tests disabled; enable by omitting --features disable-network"]
fn renew_csid_returns_request_id() {}
#[cfg(not(feature = "disable-network"))]
#[tokio::test]
async fn clear_invoice_with_live_pcsid() {
    use k256::pkcs8::DecodePrivateKey;

    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
    let csr_config = CsrProperties::parse_csr_config(&config_path).expect("csr config");

    let key_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pkeys/test_zatca_pkey.der");
    let zatca_pkey =
        k256::ecdsa::SigningKey::from_pkcs8_der(&std::fs::read(key_path).unwrap()).unwrap();
    let csr = csr_config
        .build(&zatca_pkey, EnvironmentType::NonProduction)
        .unwrap();

    let otp = "123345";
    let client = ZatcaClient::new(Config::default()).expect("client");
    let ccsid_response = client
        .post_csr_for_ccsid(&csr, otp)
        .await
        .expect("csid response");
    let pcsid_response = client
        .post_ccsid_for_pcsid(&ccsid_response)
        .await
        .expect("pcsid response");

    let signer = common::signer_from_csid(&pcsid_response.binary_security_token, &zatca_pkey);
    let invoice = {
        use chrono::TimeZone;
        use fatoora_core::invoice::{
            Address, InvoiceBuilder, InvoiceSubType, InvoiceType, LineItem, OtherId, Party,
            SellerRole, VatCategory,
        };
        use iso_currency::Currency;
        use isocountry::CountryCode;

        let seller = Party::<SellerRole>::new(
            "Acme Inc".into(),
            Address {
                country_code: CountryCode::SAU,
                city: "Riyadh".into(),
                street: "King Fahd".into(),
                additional_street: None,
                building_number: "1234".into(),
                additional_number: Some("5678".into()),
                postal_code: "12222".into(),
                subdivision: None,
                district: Some("Olaya".into()),
            },
            "399999999900003",
            Some(OtherId::with_scheme("7003339333", "CRN")),
        )
        .expect("valid seller");

        let line_items = vec![LineItem {
            description: "Item".into(),
            quantity: 1.0,
            unit_code: "PCE".into(),
            unit_price: 100.0,
            total_amount: 100.0,
            vat_rate: 15.0,
            vat_amount: 15.0,
            vat_category: VatCategory::Standard,
        }];

        let issue_datetime = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(12, 30, 0)
            .unwrap();

        InvoiceBuilder::new(
            InvoiceType::Tax(InvoiceSubType::Standard),
            "INV-0-1",
            "8e6000cf-1a98-4174-b3e7-b5d5954bc10d",
            chrono::Utc.from_utc_datetime(&issue_datetime),
            Currency::SAR,
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
            seller,
            line_items,
            "10",
            VatCategory::Standard,
        )
        .invoice_counter("0")
        .build()
        .expect("build invoice")
    };

    let signed_invoice = invoice.sign(&signer).expect("sign invoice with live pcsid");

    let clearance_response = client
        .clear_standard_invoice(&signed_invoice, &pcsid_response, true, None)
        .await
        .expect("clear signed invoice");
    println!(
        "Invoice clearance errors: {:#?}",
        clearance_response.validation_results
    );
    assert_eq!(
        clearance_response.clearance_status.unwrap(),
        "CLEARED",
        "invoice not cleared successfully"
    );
}

#[cfg(feature = "disable-network")]
#[test]
#[ignore = "network tests disabled; enable by omitting --features disable-network"]
fn clear_invoice_with_live_pcsid() {}
