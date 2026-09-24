mod support;
use fatoora_ffi::{common::ffi::BindingError, crypto::ffi::Config, invoice::ffi::Xml};
use support::written;
fn ok<T>(value: Result<T, Box<BindingError>>) -> T {
    value.unwrap_or_else(|e| panic!("{}: {}", e.code(), written(|out| e.message(out))))
}

#[test]
fn options_limit_is_in_bytes_and_invalid_options_do_not_run_validation() {
    let config = ok(Config::new(0));
    let mut options = br#"{"evaluated_at":"2026-09-23T12:00:00+03:00"}"#.to_vec();
    options.resize(4096, b' ');
    let report: serde_json::Value = serde_json::from_str(&written(|out| {
        ok(Xml::validate_zatca(
            &config,
            b"<wrong/>",
            Some(&options),
            out,
        ))
    }))
    .unwrap();
    assert_eq!(report["evaluated_at"], "2026-09-23T12:00:00+03:00");
    assert_eq!(report["is_valid"], false);
    assert_eq!(report["stages"][0]["findings"][0]["code"], "XSD_INVALID");
    options.push(b' ');
    for invalid in [
        options.as_slice(),
        b"{\"unknown\":true}",
        b"null",
        b"{}\0",
        b"\xff",
        br#"{"evaluated_at":"bad"}"#,
    ] {
        let output = written(|out| {
            let error = Xml::validate_zatca(&config, b"<wrong/>", Some(invalid), out)
                .err()
                .unwrap();
            assert_eq!(error.code(), 1);
        });
        assert!(
            output.is_empty(),
            "invalid options must not produce a report"
        );
    }
}

#[test]
fn malformed_xml_error_keeps_partial_report_and_does_not_poison_next_call() {
    let config = ok(Config::new(0));
    written(|out| {
        let error = Xml::validate_zatca(&config, b"<Invoice", None, out)
            .err()
            .unwrap();
        let details: serde_json::Value =
            serde_json::from_str(&written(|out| error.details_json(out))).unwrap();
        assert_eq!(details["report"]["is_valid"], false);
        assert_eq!(details["report"]["is_complete"], false);
        assert_eq!(details["report"]["stages"].as_array().unwrap().len(), 6);
    });
    let report: serde_json::Value = serde_json::from_str(&written(|out| {
        ok(Xml::validate_zatca(&config, b"<wrong/>", None, out))
    }))
    .unwrap();
    assert_eq!(report["has_errors"], true);
    assert_eq!(report["stages"][0]["status"], "completed");
    assert!(
        report["stages"].as_array().unwrap()[1..]
            .iter()
            .all(|stage| stage["status"] == "not_run")
    );
}
