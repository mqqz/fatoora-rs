//! Credential issuance and renewal through generated bindings and a local gateway.
mod support;
use base64ct::{Base64, Encoding};
use fatoora_ffi::{
    api::ffi::*,
    common::ffi::BindingError,
    crypto::ffi::{Config, Csr, CsrProperties, SigningKey},
};
use httpmock::{
    Method::{PATCH, POST},
    MockServer,
};
use serde_json::json;
use support::written;

const KEY: &[u8] =
    include_bytes!("../../fatoora-core/tests/fixtures/sdk-parity/credentials/private-key.der");
const PROPERTIES: &[u8] = include_bytes!(
    "../../fatoora-core/tests/fixtures/csr-configs/csr-config-example-EN.properties"
);
fn ok<T>(result: Result<T, Box<BindingError>>) -> T {
    result.unwrap_or_else(|e| panic!("{}: {}", e.code(), written(|out| e.message(out))))
}
fn csr() -> Box<Csr> {
    let props = ok(CsrProperties::from_properties_str(PROPERTIES));
    let key = ok(SigningKey::from_der(KEY));
    ok(props.build(&key, 1))
}

#[test]
fn credentials_issue_renew_and_recover_from_gateway_errors() {
    if std::env::var_os("FATOORA_CREDENTIAL_CHILD").is_some() {
        exercise_client();
        return;
    }
    let server = MockServer::start();
    let csr = csr();
    let pem = written(|out| ok(csr.to_pem(out)));
    let encoded = Base64::encode_string(pem.as_bytes());
    let issuance = server.mock(|when, then| {
        when.method(POST)
            .path("/compliance")
            .header("OTP", "123456")
            .header("Accept-Version", "V2")
            .json_body(json!({"csr":encoded}));
        then.status(200)
            .json_body(json!({"requestID":42,"binarySecurityToken":"ctoken","secret":"csecret"}));
    });
    let production = server.mock(|when, then| {
        when.method(POST)
            .path("/production/csids")
            .header(
                "Authorization",
                format!("Basic {}", Base64::encode_string(b"ctoken:csecret")),
            )
            .json_body(json!({"compliance_request_id":"42"}));
        then.status(200).json_body(
            json!({"requestID":"0077","binarySecurityToken":"ptoken","secret":"psecret"}),
        );
    });
    let mut renewal = Vec::new();
    for (otp, status, body) in [
        ("direct", 200, json!({"requestID":88,"binarySecurityToken":"new-token","secret":"new-secret"}).to_string()),
        ("wrapped", 428, json!({"value":{"requestID":88,"binarySecurityToken":"new-token","secret":"new-secret"}}).to_string()),
        ("unauthorized", 401, "expired credential".into()),
        ("unavailable", 503, "maintenance".into()),
        ("malformed", 200, "{broken".into()),
    ] {
        renewal.push(server.mock(|when, then| {
            when.method(PATCH).path("/production/csids").header("OTP", otp)
                .header("Accept-Language", "ar").header("Accept-Version", "V2")
                .header("Authorization", format!("Basic {}", Base64::encode_string(b"ptoken:psecret")))
                .json_body(json!({"csr":encoded}));
            then.status(status).body(body);
        }));
    }
    let unexpected = server.mock(|_when, then| {
        then.status(500).body("unexpected request");
    });
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "credentials_issue_renew_and_recover_from_gateway_errors",
            "--nocapture",
        ])
        .env("FATOORA_CREDENTIAL_CHILD", "1")
        .env("FATOORA_ZATCA_BASE_URL", server.base_url())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    issuance.assert_hits(1);
    production.assert_hits(1);
    for mock in renewal {
        mock.assert_hits(1);
    }
    unexpected.assert_hits(0);
}

fn exercise_client() {
    let config = ok(Config::new(1));
    let client = ok(ZatcaClient::create(&config));
    let csr = csr();
    let compliance = ok(client.post_csr_for_ccsid(&csr, b"123456"));
    assert_eq!(compliance.env(), 1);
    assert_eq!(
        written(|out| ok(ok(compliance.request_id()).unwrap().value(out))),
        "42"
    );
    assert_eq!(
        written(|out| ok(compliance.binary_security_token(out))),
        "ctoken"
    );
    assert_eq!(written(|out| ok(compliance.secret(out))), "csecret");
    let production = ok(client.post_ccsid_for_pcsid(&compliance));
    drop(compliance);
    assert_eq!(production.env(), 1);
    assert_eq!(
        written(|out| ok(ok(production.request_id()).unwrap().value(out))),
        "0077"
    );
    for (otp, expected_type) in [
        (b"unauthorized".as_slice(), "api_unauthorized"),
        (b"unavailable", "api_server"),
        (b"malformed", "invalid_response"),
    ] {
        let error = client
            .renew_csid(&production, &csr, otp, Some(b"ar"))
            .err()
            .unwrap();
        assert_eq!(
            error.code(),
            match otp {
                b"unauthorized" => 8,
                b"malformed" => 3,
                _ => 10,
            }
        );
        let details: serde_json::Value =
            serde_json::from_str(&written(|out| error.details_json(out))).unwrap();
        assert_eq!(details["type"], expected_type);
        if otp == b"unauthorized" {
            assert_eq!(details["response"]["status"], 401);
            assert_eq!(details["response"]["message"], "expired credential");
        }
        if otp == b"unavailable" {
            assert_eq!(details["response"]["code"], "ServerError");
            assert_eq!(details["response"]["message"], "maintenance");
        }
    }
    for otp in [b"direct".as_slice(), b"wrapped"] {
        let renewed = ok(client.renew_csid(&production, &csr, otp, Some(b"ar")));
        assert_eq!(renewed.env(), 1);
        assert_eq!(
            written(|out| ok(ok(renewed.request_id()).unwrap().value(out))),
            "88"
        );
        assert_eq!(
            written(|out| ok(renewed.binary_security_token(out))),
            "new-token"
        );
        assert_eq!(written(|out| ok(renewed.secret(out))), "new-secret");
    }
    // Renewal returns a new credential; neither errors nor success mutate its input.
    assert_eq!(
        written(|out| ok(production.binary_security_token(out))),
        "ptoken"
    );
    assert_eq!(written(|out| ok(production.secret(out))), "psecret");
    for bad in [b"bad\0".as_slice(), &[255]] {
        assert_eq!(
            client.post_csr_for_ccsid(&csr, bad).err().unwrap().code(),
            1
        );
        assert_eq!(
            client
                .renew_csid(&production, &csr, bad, None)
                .err()
                .unwrap()
                .code(),
            1
        );
        assert_eq!(
            client
                .renew_csid(&production, &csr, b"direct", Some(bad))
                .err()
                .unwrap()
                .code(),
            1
        );
    }
    let wrong_env = ok(CsidProduction::create(2, None, b"ptoken", b"psecret"));
    assert_eq!(
        client
            .renew_csid(&wrong_env, &csr, b"direct", Some(b"ar"))
            .err()
            .unwrap()
            .code(),
        9
    );
}
