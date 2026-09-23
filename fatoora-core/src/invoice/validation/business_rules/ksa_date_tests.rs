use super::{
    FailureKind, Limits,
    ksa_dates::KsaDateCheck as K,
    xml::{CAC, CBC, UBL, XmlView},
};
use chrono::{DateTime, FixedOffset};
fn run(check: K, body: &str, now: &str) -> Result<Vec<bool>, FailureKind> {
    let xml = XmlView::parse(
        &format!("<Invoice xmlns='{UBL}' xmlns:cac='{CAC}' xmlns:cbc='{CBC}'>{body}</Invoice>"),
        &Limits::default(),
    )
    .unwrap();
    let now: DateTime<FixedOffset> = now.parse().unwrap();
    check
        .contexts(&xml)
        .into_iter()
        .map(|n| check.passes(&xml, n, &now, 4096))
        .collect()
}
const NOW: &str = "2026-09-23T10:00:00+03:00";
#[test]
fn simplified_deadline_uses_exact_seconds_fraction_and_implicit_timezone() {
    for (time, expected) in [
        ("10:00:00", true),
        ("09:59:59.999999999999", false),
        ("10:00:00.000000000001", true),
        ("07:00:00Z", true),
        ("09:59:59Z", true),
        ("06:59:59.999999999999Z", false),
    ] {
        let body = format!(
            "<cbc:InvoiceTypeCode name='0200000'/><cbc:IssueDate>2026-09-22</cbc:IssueDate><cbc:IssueTime>{time}</cbc:IssueTime>"
        );
        assert_eq!(
            run(K::SubmissionDeadline, &body, NOW),
            Ok(vec![expected]),
            "{time}"
        );
    }
    assert_eq!(
        run(
            K::SubmissionDeadline,
            "<cbc:InvoiceTypeCode name='0100000'/><cbc:IssueDate>bad</cbc:IssueDate><cbc:IssueTime>bad</cbc:IssueTime>",
            NOW
        ),
        Ok(vec![true])
    );
    assert_eq!(
        run(
            K::SubmissionDeadline,
            "<cbc:InvoiceTypeCode name='0200000'/><cbc:IssueDate>bad</cbc:IssueDate><cbc:IssueTime>bad</cbc:IssueTime>",
            NOW
        ),
        Err(FailureKind::InvalidDateTime)
    );
    assert_eq!(
        run(
            K::SubmissionDeadline,
            "<cbc:InvoiceTypeCode name='0200000'/><cbc:IssueDate>2026-09-21</cbc:IssueDate><cbc:IssueTime>24:00:00</cbc:IssueTime>",
            NOW
        ),
        Ok(vec![false])
    );
}
#[test]
fn root_issue_time_is_stricter_than_prepayment_time_castability() {
    for (time, root, prepaid) in [
        ("09:15:00", true, true),
        ("09:15:00Z", true, true),
        ("09:15:00+03:00", false, true),
        ("09:15:00.123456789123", false, true),
        ("24:00:00", false, true),
        ("24:00:00.000", false, true),
        ("24:00:00.001", false, false),
        ("24:00:00.000000000999", false, true),
        ("24:00:00.0000000011", false, false),
        ("09:15:60", false, false),
        ("09:15:00+14:01", false, true),
        ("09:15:00+15:00", false, false),
        ("09:15:00-14:00", false, true),
        (" 09:15:00 ", false, true),
        ("09:15:00.", false, false),
        ("", false, false),
    ] {
        assert_eq!(
            run(
                K::IssueTime,
                &format!("<cbc:IssueTime>{time}</cbc:IssueTime>"),
                NOW
            ),
            Ok(vec![root]),
            "{time}"
        );
        assert_eq!(
            run(
                K::PrepaymentTime,
                &format!(
                    "<cac:InvoiceLine><cac:DocumentReference><cbc:IssueTime>{time}</cbc:IssueTime></cac:DocumentReference></cac:InvoiceLine>"
                ),
                NOW
            ),
            Ok(vec![prepaid]),
            "{time}"
        );
    }
}
#[test]
fn future_dates_compare_timezone_adjusted_midnights_and_castable_guard() {
    for (date, expected) in [
        ("2026-09-23", true),
        ("2026-09-24", false),
        ("2026-09-23Z", false),
        ("2026-09-23+04:00", true),
        ("2026-09-22-14:00", true),
        ("bad", true),
        ("2100-02-29", true),
        (" 2026-09-23 ", true),
    ] {
        assert_eq!(
            run(
                K::FutureIssueDate,
                &format!("<cbc:IssueDate>{date}</cbc:IssueDate>"),
                NOW
            ),
            Ok(vec![expected]),
            "{date}"
        );
    }
    assert_eq!(
        run(
            K::FutureIssueDate,
            "<cbc:IssueDate>1000000-01-01</cbc:IssueDate>",
            NOW
        ),
        Err(FailureKind::Limit("date year"))
    );
}
#[test]
fn date_format_retains_source_leap_year_regex_and_raw_whitespace() {
    for (date, expected) in [
        ("2000-02-29", true),
        ("2100-02-29", true),
        ("2023-02-29", false),
        ("2024-04-31", false),
        ("1999-01-01", false),
        ("9999-12-31", true),
        ("2024-01-01Z", false),
        (" 2024-01-01", false),
        ("2024-01-01", true),
    ] {
        assert_eq!(
            run(
                K::DateFormat,
                &format!("<cbc:IssueDate>{date}</cbc:IssueDate>"),
                NOW
            ),
            Ok(vec![expected]),
            "{date}"
        );
    }
}
#[test]
fn delivery_order_checks_only_source_calendar_range() {
    for (start, end, expected) in [
        ("2024-02-10", "2024-02-10", true),
        ("2024-02-11", "2024-02-10", false),
        ("2100-02-11", "2100-02-10", true),
        ("1900-02-29", "1900-02-28", true),
        ("2000-02-29", "2000-02-28", false),
        (" 2024-02-11 ", "2024-02-10", true),
    ] {
        assert_eq!(
            run(
                K::DeliveryOrder,
                &format!(
                    "<cac:Delivery><cbc:ActualDeliveryDate>{start}</cbc:ActualDeliveryDate><cbc:LatestDeliveryDate>{end}</cbc:LatestDeliveryDate></cac:Delivery>"
                ),
                NOW
            ),
            Ok(vec![expected])
        );
    }
    assert_eq!(
        run(
            K::DeliveryOrder,
            "<cac:Delivery><cbc:ActualDeliveryDate>2024-02-11</cbc:ActualDeliveryDate><cbc:ActualDeliveryDate>2024-02-11</cbc:ActualDeliveryDate><cbc:LatestDeliveryDate>2024-02-10</cbc:LatestDeliveryDate></cac:Delivery>",
            NOW
        ),
        Err(FailureKind::Cardinality)
    );
}

#[test]
fn date_guards_precede_singleton_casts_and_calendar_years_are_astronomical() {
    assert_eq!(
        run(
            K::SubmissionDeadline,
            "<cbc:InvoiceTypeCode name='0200000'/><cbc:IssueDate>bad</cbc:IssueDate><cbc:IssueDate>bad</cbc:IssueDate>",
            NOW
        ),
        Ok(vec![true])
    );
    assert_eq!(
        run(K::IssueTime, "<cbc:IssueTime/><cbc:IssueTime/>", NOW),
        Ok(vec![false])
    );
    for date in ["0000-02-29", "-0000-02-29", "-0004-02-29"] {
        assert_eq!(
            run(
                K::SubmissionDeadline,
                &format!(
                    "<cbc:InvoiceTypeCode name='0200000'/><cbc:IssueDate>{date}</cbc:IssueDate><cbc:IssueTime>00:00:00</cbc:IssueTime>"
                ),
                NOW
            ),
            Ok(vec![false])
        );
    }
    assert_eq!(
        run(
            K::SubmissionDeadline,
            "<cbc:InvoiceTypeCode name='0200000'/><cbc:IssueDate>-0001-02-29</cbc:IssueDate><cbc:IssueTime>00:00:00</cbc:IssueTime>",
            NOW
        ),
        Err(FailureKind::InvalidDateTime)
    );
}
