//! Temporal checks from the pinned KSA profile, evaluated against one caller clock.
//! Source expressions retain LGPL-3.0 terms recorded in the source catalog.
use super::{
    FailureKind,
    decimal::ExactDecimal,
    xml::{CBC, NodeId, XmlView, a, b, is_xml_space, normalize_space},
};
use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone};
use regex::Regex;
use std::sync::LazyLock;
#[derive(Debug, Clone, Copy)]
pub(super) enum KsaDateCheck {
    SubmissionDeadline,
    IssueTime,
    FutureIssueDate,
    DeliveryOrder,
    DateFormat,
    PrepaymentTime,
}
impl KsaDateCheck {
    pub fn contexts(self, xml: &XmlView) -> Vec<NodeId> {
        use KsaDateCheck::*;
        match self {
            SubmissionDeadline | IssueTime => {
                if xml.is_document_root(0) {
                    vec![0]
                } else {
                    vec![]
                }
            }
            FutureIssueDate => xml.all(CBC, "IssueDate"),
            DeliveryOrder => xml.all_path(&[a("Delivery"), b("LatestDeliveryDate")]),
            PrepaymentTime => {
                xml.all_path(&[a("InvoiceLine"), a("DocumentReference"), b("IssueTime")])
            }
            DateFormat => {
                let mut nodes = vec![];
                for field in ["IssueDate", "DueDate", "TaxPointDate"] {
                    nodes.extend(xml.all(CBC, field));
                }
                for field in ["ActualDeliveryDate", "LatestDeliveryDate"] {
                    nodes.extend(xml.all_path(&[a("Delivery"), b(field)]));
                }
                nodes.sort_unstable();
                nodes.dedup();
                nodes
            }
        }
    }
    pub fn passes(
        self,
        xml: &XmlView,
        node: NodeId,
        now: &DateTime<FixedOffset>,
        digits: usize,
    ) -> Result<bool, FailureKind> {
        use KsaDateCheck::*;
        let local = |field| xml.singleton_text(&xml.path(node, &[b(field)]));
        Ok(match self {
            SubmissionDeadline => {
                if !xml.path(node, &[b("InvoiceTypeCode")]).iter().any(|&n| {
                    xml.attribute(n, "", "name")
                        .is_some_and(|v| v.starts_with("02"))
                }) {
                    return Ok(true);
                }
                if xml.path(node, &[b("IssueDate")]).is_empty()
                    || xml.path(node, &[b("IssueTime")]).is_empty()
                {
                    return Ok(true);
                }
                let (Some(date), Some(time)) = (local("IssueDate")?, local("IssueTime")?) else {
                    return Ok(true);
                };
                let joined = format!("{date}T{time}");
                let joined = joined.trim_matches(is_xml_space);
                let (date, time) = joined.split_once('T').ok_or(FailureKind::InvalidDateTime)?;
                let (mut date, date_zone) = parse_date(date)?;
                if date_zone.is_some() {
                    return Err(FailureKind::InvalidDateTime);
                }
                let time = parse_time(time, digits)?;
                if time.next_day {
                    date = date.succ_opt().ok_or(FailureKind::Limit("date year"))?;
                }
                let issue_seconds = date.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp()
                    + time.seconds as i64
                    - time.zone.unwrap_or(*now.offset()).local_minus_utc() as i64;
                let issue = ExactDecimal::from_i64(issue_seconds).add(&time.fraction, digits)?;
                let cutoff = ExactDecimal::from_i64(now.timestamp() - 86400).add(
                    &ExactDecimal::from_i64(now.timestamp_subsec_nanos() as i64)
                        .scale_down(9, digits)?,
                    digits,
                )?;
                issue >= cutoff
            }
            IssueTime => {
                if !xml
                    .path(node, &[b("IssueTime")])
                    .iter()
                    .any(|&n| !xml.node(n).text.is_empty())
                {
                    return Ok(false);
                }
                let Some(value) = local("IssueTime")? else {
                    return Ok(false);
                };
                static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
                    Regex::new(r"\A([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z?\z").unwrap()
                });
                PATTERN.is_match(value)
            }
            FutureIssueDate => {
                let value = xml.node(node).text.trim_matches(is_xml_space);
                let (date, zone) = match parse_date(value) {
                    Ok(v) => v,
                    Err(FailureKind::InvalidDateTime) => return Ok(true),
                    Err(e) => return Err(e),
                };
                let value = date.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp()
                    - zone.unwrap_or(*now.offset()).local_minus_utc() as i64;
                let today = now
                    .offset()
                    .from_local_datetime(&now.date_naive().and_hms_opt(0, 0, 0).unwrap())
                    .single()
                    .unwrap()
                    .timestamp();
                value <= today
            }
            DeliveryOrder => {
                let parent = xml.node(node).parent.expect("delivery child");
                let Some(actual) =
                    xml.singleton_text(&xml.path(parent, &[b("ActualDeliveryDate")]))?
                else {
                    return Ok(true);
                };
                let latest = &xml.node(node).text;
                if normalize_space(actual).is_empty()
                    || !delivery_calendar(actual)
                    || !delivery_calendar(latest)
                {
                    return Ok(true);
                }
                parse_date(latest)?.0 >= parse_date(actual)?.0
            }
            DateFormat => date_format(&xml.node(node).text),
            PrepaymentTime => {
                match parse_time(xml.node(node).text.trim_matches(is_xml_space), digits) {
                    Ok(_) => true,
                    Err(FailureKind::InvalidDateTime) => false,
                    Err(e) => return Err(e),
                }
            }
        })
    }
}
fn date_format(value: &str) -> bool {
    let Some((y, m, d)) = lexical_date(value) else {
        return false;
    };
    (2000..=9999).contains(&y)
        && d > 0
        && d <= match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if y % 4 == 0 => 29,
            2 => 28,
            _ => 0,
        }
}
fn delivery_calendar(value: &str) -> bool {
    lexical_date(value).is_some_and(|(y, m, d)| {
        (1800..=2099).contains(&y) && NaiveDate::from_ymd_opt(y, m, d).is_some()
    })
}
fn lexical_date(value: &str) -> Option<(i32, u32, u32)> {
    let v = value.as_bytes();
    if v.len() != 10
        || v[4] != b'-'
        || v[7] != b'-'
        || !v
            .iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    {
        return None;
    }
    Some((
        value[..4].parse().ok()?,
        value[5..7].parse().ok()?,
        value[8..].parse().ok()?,
    ))
}
fn zone(value: &str) -> Result<Option<FixedOffset>, FailureKind> {
    if value.is_empty() {
        return Ok(None);
    }
    if value == "Z" {
        return Ok(FixedOffset::east_opt(0));
    }
    let v = value.as_bytes();
    if v.len() != 6
        || !matches!(v[0], b'+' | b'-')
        || v[3] != b':'
        || ![v[1], v[2], v[4], v[5]].iter().all(u8::is_ascii_digit)
    {
        return Err(FailureKind::InvalidDateTime);
    }
    let h = (v[1] - b'0') as i32 * 10 + (v[2] - b'0') as i32;
    let m = (v[4] - b'0') as i32 * 10 + (v[5] - b'0') as i32;
    // The pinned SDK cast accepts offsets through 14:59; its XSD stage
    // rejects offsets beyond 14:00. Preserve each stage independently.
    if h > 14 || m > 59 {
        return Err(FailureKind::InvalidDateTime);
    }
    Ok(FixedOffset::east_opt(
        (h * 3600 + m * 60) * if v[0] == b'-' { -1 } else { 1 },
    ))
}
fn parse_date(value: &str) -> Result<(NaiveDate, Option<FixedOffset>), FailureKind> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\A(-?)([0-9]{4,})-([0-9]{2})-([0-9]{2})(Z|[+-][0-9]{2}:[0-9]{2})?\z").unwrap()
    });
    let c = PATTERN
        .captures(value)
        .ok_or(FailureKind::InvalidDateTime)?;
    let year = &c[2];
    if year.len() > 4 && year.starts_with('0') {
        return Err(FailureKind::InvalidDateTime);
    }
    if year.len() > 6 {
        return Err(FailureKind::Limit("date year"));
    }
    let mut year: i32 = year.parse().map_err(|_| FailureKind::InvalidDateTime)?;
    if &c[1] == "-" {
        year = -year;
    }
    if !(-262143..=262142).contains(&year) {
        return Err(FailureKind::Limit("date year"));
    }
    let date = NaiveDate::from_ymd_opt(year, c[3].parse().unwrap(), c[4].parse().unwrap())
        .ok_or(FailureKind::InvalidDateTime)?;
    Ok((date, zone(c.get(5).map_or("", |v| v.as_str()))?))
}
struct ParsedTime {
    seconds: u32,
    fraction: ExactDecimal,
    next_day: bool,
    zone: Option<FixedOffset>,
}
fn parse_time(value: &str, digits: usize) -> Result<ParsedTime, FailureKind> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\A([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?\z")
            .unwrap()
    });
    let c = PATTERN
        .captures(value)
        .ok_or(FailureKind::InvalidDateTime)?;
    let h: u32 = c[1].parse().unwrap();
    let m: u32 = c[2].parse().unwrap();
    let s: u32 = c[3].parse().unwrap();
    let raw_fraction = c.get(4).map_or("0", |v| v.as_str());
    if raw_fraction.len().saturating_sub(1) > digits {
        return Err(FailureKind::Limit("decimal digits"));
    }
    // The pinned SDK date/time value model retains nanoseconds, truncating
    // additional fractional digits before midnight validation and arithmetic.
    let fraction = ExactDecimal::parse(&raw_fraction[..raw_fraction.len().min(10)], digits)?;
    if h > 24
        || m > 59
        || s > 59
        || (h == 24 && (m != 0 || s != 0 || fraction != ExactDecimal::zero()))
    {
        return Err(FailureKind::InvalidDateTime);
    }
    Ok(ParsedTime {
        seconds: h % 24 * 3600 + m * 60 + s,
        fraction,
        next_day: h == 24,
        zone: zone(c.get(5).map_or("", |v| v.as_str()))?,
    })
}
