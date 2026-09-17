//! Submission through the public client against a local HTTP server.
//! A child process isolates the base-URL environment variable from other tests.
use fatoora_core::api::{
    Compliance, CsidCredentials, InvoiceOutcome, Production, ZatcaClient, ZatcaError,
};
use fatoora_core::config::{Config, EnvironmentType};
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;
use httpmock::{Method::POST, MockServer};
use serde_json::json;

const SIMPLIFIED: &str = include_str!("fixtures/invoices/sample-simplified-invoice.xml");
const STANDARD: &str = include_str!("fixtures/invoices/Standard/Invoice/Standard_Invoice.xml");

#[test]
fn public_submission_contract() {
    let server = MockServer::start();
    for (case, endpoint, status, body) in [
        (
            "accepted",
            "reporting/single",
            200,
            json!({"validationResults": {"status": "PASS"}, "reportingStatus": "REPORTED"}),
        ),
        (
            "rejected",
            "reporting/single",
            200,
            json!({"validationResults": {"status": "ERROR"}, "reportingStatus": "NOT_REPORTED"}),
        ),
        (
            "http_error",
            "reporting/single",
            409,
            json!({"validationResults": {"status": "ERROR"}, "reportingStatus": "NOT_REPORTED", "gatewayDetail": "duplicate"}),
        ),
        (
            "clearance",
            "clearance/single",
            208,
            json!({"validationResults": {"status": "PASS"}, "clearanceStatus": "CLEARED", "clearedInvoice": "PGNsZWFyZWQvPg=="}),
        ),
        (
            "compliance",
            "compliance",
            200,
            json!({"validationResults": {"status": "PASS"}}),
        ),
    ] {
        let invoice = parse_signed_invoice_xml(if case == "clearance" {
            STANDARD
        } else {
            SIMPLIFIED
        })
        .unwrap();
        let path = if case == "compliance" {
            "/compliance/invoices".to_owned()
        } else {
            format!("/invoices/{endpoint}")
        };
        let mut mock = server.mock(|when, then| {
            when.method(POST).path(path)
                .header("authorization", "Basic dG9rZW46c2VjcmV0")
                .header("accept-version", "V2")
                .json_body(json!({"invoiceHash": invoice.invoice_hash(), "uuid": invoice.uuid(), "invoice": invoice.to_xml_base64()}));
            then.status(status).json_body(body.clone());
        });
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "submission_worker", "--ignored", "--nocapture"])
            .env("FATOORA_ZATCA_BASE_URL", server.base_url())
            .env("FATOORA_CONTRACT_CASE", case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        mock.assert();
        mock.delete();
    }
}

#[test]
#[ignore = "invoked by public_submission_contract with an isolated local endpoint"]
fn submission_worker() {
    let case = std::env::var("FATOORA_CONTRACT_CASE").expect("parent supplies scenario");
    let env = EnvironmentType::NonProduction;
    let client = ZatcaClient::new(Config::new(env)).unwrap();
    let credentials = CsidCredentials::<Production>::new(env, None, "token", "secret");
    let invoice = parse_signed_invoice_xml(if case == "clearance" {
        STANDARD
    } else {
        SIMPLIFIED
    })
    .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let result = match case.as_str() {
            "clearance" => {
                client
                    .clear_standard_invoice(&invoice, &credentials, true, Some("en"))
                    .await
            }
            "compliance" => {
                client
                    .check_invoice_compliance(
                        &invoice,
                        &CsidCredentials::<Compliance>::new(env, None, "token", "secret"),
                    )
                    .await
            }
            _ => {
                client
                    .report_simplified_invoice(&invoice, &credentials, false, Some("en"))
                    .await
            }
        };
        if case == "http_error" {
            let ZatcaError::Response(error) = result.unwrap_err() else {
                panic!("expected HTTP response error")
            };
            assert_eq!(error.http_status(), 409);
            assert!(error.body().contains("gatewayDetail"));
            assert_eq!(
                error.validation_response().unwrap().outcome(),
                InvoiceOutcome::Rejected
            );
        } else {
            let response = result.unwrap();
            if case == "rejected" {
                assert_eq!(response.http_status(), Some(200));
                assert_eq!(response.outcome(), InvoiceOutcome::Rejected);
                assert!(matches!(
                    response.ensure_accepted(),
                    Err(ZatcaError::NotAccepted(_))
                ));
            } else {
                assert_eq!(response.outcome(), InvoiceOutcome::Accepted);
                response.ensure_accepted().unwrap();
                if case == "clearance" {
                    assert_eq!(response.http_status(), Some(208));
                    assert_eq!(response.cleared_invoice_base64(), Some("PGNsZWFyZWQvPg=="));
                    assert_eq!(
                        response.cleared_invoice_xml().unwrap().as_deref(),
                        Some("<cleared/>")
                    );
                } else {
                    assert_eq!(response.http_status(), Some(200));
                }
            }
        }
    });
}
