//! Real HTTP through the blocking binding adapter. The gateway URL is installed
//! only in a child process, avoiding process-global environment races in tests.
mod support;
use base64ct::{Base64, Encoding};
use fatoora_ffi::{
    api::ffi::*, common::ffi::BindingError, crypto::ffi::Config, invoice::ffi::SignedInvoice,
};
use httpmock::{Method::POST, MockServer};
use serde_json::json;
use support::written;

const SIMPLE: &[u8] =
    include_bytes!("../../fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml");
const STANDARD: &[u8] = include_bytes!(
    "../../fatoora-core/tests/fixtures/sdk-parity/cases/standard-invoice/sdk-signed.xml"
);
fn ok<T>(value: Result<T, Box<BindingError>>) -> T {
    value.unwrap_or_else(|e| panic!("{}: {}", e.code(), written(|out| e.message(out))))
}

#[test]
fn blocking_http_contract() {
    if std::env::var_os("FATOORA_BINDING_HTTP_CHILD").is_some() {
        exercise_client();
        return;
    }
    let server = MockServer::start();
    let mut mocks = Vec::new();
    for (path, source, field, language, clearance) in [
        (
            "/invoices/reporting/single",
            SIMPLE,
            "reportingStatus",
            "ar",
            Some("0"),
        ),
        (
            "/invoices/clearance/single",
            STANDARD,
            "clearanceStatus",
            "en",
            Some("1"),
        ),
        ("/compliance/invoices", SIMPLE, "status", "en", None),
    ] {
        // Parse only to obtain fixture identity. The encoded document is checked
        // against the original bytes, independently of binding serialization.
        let invoice = fatoora_core::invoice::xml::parse::parse_signed_invoice_xml(
            std::str::from_utf8(source).unwrap(),
        )
        .unwrap();
        for (token, status, value) in [
            ("accepted", 202, "accepted"),
            ("rejected", 200, "rejected"),
            ("unknown", 200, "FUTURE"),
            ("http-error", 422, "rejected"),
        ] {
            let status_value = match (field, value) {
                ("reportingStatus", "accepted") => "REPORTED",
                ("reportingStatus", "rejected") => "NOT_REPORTED",
                ("clearanceStatus", "accepted") => "CLEARED",
                ("clearanceStatus", "rejected") => "NOT_CLEARED",
                ("status", "accepted") => "PASS",
                ("status", "rejected") => "ERROR",
                _ => value,
            };
            let mut body = json!({"validationResults":{"status":"PASS", "warningMessages":[{"code":"WARN", "message":"retained"}]}});
            if field == "status" {
                body["validationResults"][field] = status_value.into();
            } else {
                body[field] = status_value.into();
            }
            mocks.push(server.mock(|when, then| {
                let mut when = when.method(POST).path(path)
                    .header("Authorization", format!("Basic {}", Base64::encode_string(format!("{token}:secret").as_bytes())))
                    .header("Accept-Version", "V2").header("Accept-Language", language)
                    .json_body(json!({"uuid":invoice.uuid(), "invoiceHash":invoice.invoice_hash(), "invoice":Base64::encode_string(source)}));
                if let Some(value) = clearance { when = when.header("Clearance-Status", value); }
                let _ = when;
                then.status(status).json_body(body);
            }));
        }
    }
    let unexpected = server.mock(|_when, then| {
        then.status(500).body("unexpected request");
    });
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "blocking_http_contract", "--nocapture"])
        .env("FATOORA_BINDING_HTTP_CHILD", "1")
        .env("FATOORA_ZATCA_BASE_URL", server.base_url())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for mock in mocks {
        mock.assert_hits(1);
    }
    unexpected.assert_hits(0);
}

fn exercise_client() {
    let config = ok(Config::new(0));
    let client = ok(ZatcaClient::create(&config));
    let mut simple = ok(SignedInvoice::from_xml(SIMPLE));
    let standard = ok(SignedInvoice::from_xml(STANDARD));
    // Also exercise the adapter from an already-entered Tokio runtime.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        for token in ["accepted", "rejected", "unknown", "http-error"] {
            let production = ok(CsidProduction::create(0, None, token.as_bytes(), b"secret"));
            let compliance = ok(CsidCompliance::create(0, None, token.as_bytes(), b"secret"));
            for result in [
                client.report_simplified_invoice(&simple, &production, false, Some(b"ar")),
                client.clear_standard_invoice(&standard, &production, true, None),
                client.check_invoice_compliance(&simple, &compliance),
            ] {
                if token == "http-error" {
                    let error = result.err().expect("HTTP rejection must be an error");
                    assert_eq!(error.code(), 10);
                    let details: serde_json::Value =
                        serde_json::from_str(&written(|out| error.details_json(out))).unwrap();
                    assert_eq!(details["http_status"], 422);
                    assert_eq!(
                        details["response"]["validationResults"]["warningMessages"][0]["code"],
                        "WARN"
                    );
                    continue;
                }
                let response = ok(result);
                assert_eq!(
                    response.http_status(),
                    Some(if token == "accepted" { 202 } else { 200 })
                );
                assert!(matches!(
                    (token, response.outcome()),
                    ("accepted", InvoiceOutcome::Accepted)
                        | ("rejected", InvoiceOutcome::Rejected)
                        | ("unknown", InvoiceOutcome::Unknown)
                ));
                assert_eq!(response.ensure_accepted().is_ok(), token == "accepted");
                let results = ok(response.validation_results());
                drop(response);
                let warning = ok(results.warning_message(0));
                drop(results);
                assert_eq!(
                    written(|out| ok(ok(warning.message()).unwrap().value(out))),
                    "retained"
                );
            }
        }
    });
    let production = ok(CsidProduction::create(0, None, b"accepted", b"secret"));
    let compliance = ok(CsidCompliance::create(0, None, b"accepted", b"secret"));
    // Rejected calls must not make additional requests or consume the invoice.
    assert!(
        client
            .clear_standard_invoice(&simple, &production, false, None)
            .is_err()
    );
    assert!(
        client
            .report_simplified_invoice(&standard, &production, false, None)
            .is_err()
    );
    let wrong_env = ok(CsidProduction::create(1, None, b"accepted", b"secret"));
    assert!(
        client
            .report_simplified_invoice(&simple, &wrong_env, false, None)
            .is_err()
    );
    assert_eq!(
        client
            .report_simplified_invoice(&simple, &production, false, Some(b"ar\0"))
            .err()
            .unwrap()
            .code(),
        1
    );
    assert_eq!(written(|out| ok(simple.xml(out))).as_bytes(), SIMPLE);
    written(|out| ok(simple.into_xml(out)));
    assert_eq!(
        client
            .report_simplified_invoice(&simple, &production, false, None)
            .err()
            .unwrap()
            .code(),
        1
    );
    assert_eq!(
        client
            .clear_standard_invoice(&simple, &production, false, None)
            .err()
            .unwrap()
            .code(),
        1
    );
    assert_eq!(
        client
            .check_invoice_compliance(&simple, &compliance)
            .err()
            .unwrap()
            .code(),
        1
    );
    assert!(client.post_ccsid_for_pcsid(&compliance).is_err());
}
