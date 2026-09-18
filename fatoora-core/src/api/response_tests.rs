use super::*;
use base64ct::Encoding;
use httpmock::{Method::GET, MockServer};

async fn receive(
    status: u16,
    body: &str,
    operation: InvoiceOperation,
) -> Result<ValidationResponse, ZatcaError> {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/");
            then.status(status).body(body);
        })
        .await;
    let response = reqwest::get(server.url("/")).await.unwrap();
    let result = read_validation_response(response, operation).await;
    mock.assert_async().await;
    result
}

#[tokio::test]
async fn response_contract_preserves_rejections_and_status() {
    let body = r#"{"validationResults":{"status":"ERROR","errorMessages":[{"code":"BR-KSA-37","message":"invalid address"}]},"reportingStatus":"NOT_REPORTED"}"#;
    for status in [400, 409, 401, 403, 406, 429, 500, 503] {
        let err = receive(status, body, InvoiceOperation::Reporting)
            .await
            .unwrap_err();
        assert_eq!(err.http_status(), Some(status));
        let ZatcaError::Response(response) = &err else {
            panic!("{err:?}")
        };
        assert_eq!(response.body(), body);
        assert_eq!(
            response
                .validation_response()
                .unwrap()
                .validation_results()
                .error_messages()[0]
                .code(),
            Some("BR-KSA-37")
        );
        let details: serde_json::Value =
            serde_json::from_str(&crate::Error::from(err).details_json()).unwrap();
        assert_eq!(details["http_status"], status);
        assert_eq!(
            details["response"]["validationResults"]["errorMessages"][0]["code"],
            "BR-KSA-37"
        );
    }
}

#[tokio::test]
async fn response_contract_http_success_is_separate_from_acceptance() {
    for (operation, status_field, accepted, rejected) in [
        (
            InvoiceOperation::Reporting,
            "reportingStatus",
            "REPORTED",
            "NOT_REPORTED",
        ),
        (
            InvoiceOperation::Clearance,
            "clearanceStatus",
            "CLEARED",
            "NOT_CLEARED",
        ),
        (InvoiceOperation::Compliance, "status", "PASS", "ERROR"),
    ] {
        for (value, expected) in [
            (accepted, InvoiceOutcome::Accepted),
            (rejected, InvoiceOutcome::Rejected),
            ("FUTURE", InvoiceOutcome::Unknown),
        ] {
            let mut body = serde_json::json!({"validationResults":{"status":"WARNING", "warningMessages":[{"code":"WARNING"}]}});
            if operation == InvoiceOperation::Compliance {
                body["validationResults"][status_field] = value.into();
            } else {
                body[status_field] = value.into();
            }
            let response = receive(202, &body.to_string(), operation).await.unwrap();
            assert_eq!(response.http_status(), Some(202));
            assert_eq!(response.outcome(), expected);
            assert_eq!(
                response.ensure_accepted().is_ok(),
                expected == InvoiceOutcome::Accepted
            );
        }
    }
    let response = receive(
        200,
        r#"{"validationResults":{"status":"PASS"},"clearanceStatus":"CLEARED"}"#,
        InvoiceOperation::Reporting,
    )
    .await
    .unwrap();
    assert_eq!(response.outcome(), InvoiceOutcome::Unknown);
    let detached: ValidationResponse = serde_json::from_str(
        r#"{"validationResults":{"status":"PASS"},"reportingStatus":"REPORTED"}"#,
    )
    .unwrap();
    assert_eq!(detached.http_status(), None);
    assert_eq!(detached.outcome(), InvoiceOutcome::Unknown);
}

#[tokio::test]
async fn response_contract_preserves_cleared_xml_and_decode_failures() {
    let xml = "<Invoice>\n  exact content\n</Invoice>\n";
    let encoded = base64ct::Base64::encode_string(xml.as_bytes());
    for value in [
        Some(encoded.as_str()),
        None,
        Some("%%%"),
        Some("/w=="),
        Some("AA=="),
        Some(""),
    ] {
        let body = serde_json::json!({"validationResults":{},"clearanceStatus":"CLEARED","clearedInvoice":value});
        let response = receive(200, &body.to_string(), InvoiceOperation::Clearance)
            .await
            .unwrap();
        assert_eq!(response.cleared_invoice_base64(), value);
        assert_eq!(response.outcome(), InvoiceOutcome::Accepted);
        match value {
            Some(v) if v == encoded => assert_eq!(
                response.cleared_invoice_xml().unwrap().as_deref(),
                Some(xml)
            ),
            None => assert_eq!(response.cleared_invoice_xml().unwrap(), None),
            _ => {
                let err = response.cleared_invoice_xml().unwrap_err();
                assert_eq!(err.kind(), crate::ErrorKind::Parse);
                assert_eq!(err.http_status(), Some(200));
            }
        }
    }
}

#[tokio::test]
async fn response_contract_keeps_malformed_bodies() {
    for status in [200, 204, 400, 502] {
        for body in ["", "<html>gateway failure</html>", "{broken"] {
            if status == 204 && !body.is_empty() {
                continue;
            }
            let err = receive(status, body, InvoiceOperation::Reporting)
                .await
                .unwrap_err();
            assert_eq!(err.http_status(), Some(status));
            let details: serde_json::Value =
                serde_json::from_str(&crate::Error::from(err).details_json()).unwrap();
            assert_eq!(details["body"], body);
        }
    }
}

#[tokio::test]
async fn response_contract_redirect_is_not_followed() {
    let server = MockServer::start_async().await;
    let target = server
        .mock_async(|when, then| {
            when.path("/target");
            then.status(200);
        })
        .await;
    let redirect = server
        .mock_async(|when, then| {
            when.path("/redirect");
            then.status(303)
                .header("Location", server.url("/target"))
                .body("clearance disabled");
        })
        .await;
    let client = ZatcaClient::new(Config::default()).unwrap();
    let response = client
        ._client
        .get(server.url("/redirect"))
        .send()
        .await
        .unwrap();
    let err = read_validation_response(response, InvoiceOperation::Clearance)
        .await
        .unwrap_err();
    assert_eq!(err.http_status(), Some(303));
    redirect.assert_async().await;
    target.assert_hits_async(0).await;
}

#[tokio::test]
async fn response_contract_duplicate_clearance_and_contradictions() {
    let body = r#"{"validationResults":{"status":"WARNING","warningMessages":[{"code":"warning"}]},"clearanceStatus":"CLEARED","clearedInvoice":"PEludm9pY2UvPg=="}"#;
    let response = receive(208, body, InvoiceOperation::Clearance)
        .await
        .unwrap();
    assert_eq!(response.http_status(), Some(208));
    response.ensure_accepted().unwrap();
    assert_eq!(
        response.cleared_invoice_xml().unwrap().as_deref(),
        Some("<Invoice/>")
    );
    for body in [
        r#"{"validationResults":{"status":"ERROR"},"reportingStatus":"REPORTED"}"#,
        r#"{"validationResults":{"status":"PASS","errorMessages":[{"code":"error"}]},"reportingStatus":"REPORTED"}"#,
    ] {
        let response = receive(200, body, InvoiceOperation::Reporting)
            .await
            .unwrap();
        assert_eq!(response.outcome(), InvoiceOutcome::Unknown);
        let err = response.ensure_accepted().unwrap_err();
        assert_eq!(err.http_status(), Some(200));
    }
    let response = receive(
        200,
        r#"{"validationResults":{"status":"WARNING"}}"#,
        InvoiceOperation::Compliance,
    )
    .await
    .unwrap();
    response.ensure_accepted().unwrap();
    let detached: ValidationResponse = serde_json::from_str(r#"{"validationResults":{},"http_status":200,"operation":"Reporting","reportingStatus":"REPORTED"}"#).unwrap();
    assert_eq!(detached.http_status(), None);
    assert_eq!(detached.outcome(), InvoiceOutcome::Unknown);
}

#[tokio::test]
async fn response_contract_body_read_failure_keeps_status() {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = BufReader::new(&mut stream);
        let mut line = String::new();
        loop {
            line.clear();
            assert!(request.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
        }
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\nConnection: close\r\n\r\n{partial",
            )
            .unwrap();
    });
    let response = reqwest::get(format!("http://{address}")).await.unwrap();
    let err = read_validation_response(response, InvoiceOperation::Reporting)
        .await
        .unwrap_err();
    server.join().unwrap();
    assert!(matches!(
        err,
        ZatcaError::ResponseRead {
            http_status: 200,
            ..
        }
    ));
    assert_eq!(err.kind(), crate::ErrorKind::Network);
}

#[tokio::test]
async fn response_contract_all_invoice_endpoints_reject_http_400() {
    let server = MockServer::start_async().await;
    let mut client = ZatcaClient::new(Config::default()).unwrap();
    client.base_url = format!("{}/", server.base_url());
    let body = r#"{"validationResults":{"status":"ERROR","errorMessages":[{"code":"REJECTED"}]}}"#;
    let mock = server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST);
            then.status(400).body(body);
        })
        .await;
    let simplified = super::tests::build_signed_invoice(crate::invoice::InvoiceType::Tax(
        crate::invoice::InvoiceSubType::Simplified,
    ));
    let standard = super::tests::build_signed_invoice(crate::invoice::InvoiceType::Tax(
        crate::invoice::InvoiceSubType::Standard,
    ));
    let pcsid = CsidCredentials::new(EnvironmentType::NonProduction, None, "token", "secret");
    let ccsid = CsidCredentials::new(EnvironmentType::NonProduction, None, "token", "secret");
    assert_eq!(
        client
            .report_simplified_invoice(&simplified, &pcsid, false, None)
            .await
            .unwrap_err()
            .http_status(),
        Some(400)
    );
    assert_eq!(
        client
            .clear_standard_invoice(&standard, &pcsid, true, None)
            .await
            .unwrap_err()
            .http_status(),
        Some(400)
    );
    assert_eq!(
        client
            .check_invoice_compliance(&simplified, &ccsid)
            .await
            .unwrap_err()
            .http_status(),
        Some(400)
    );
    mock.assert_hits_async(3).await;
}
