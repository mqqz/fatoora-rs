use super::*;

fn check(site: usize, body: &str) -> Result<usize, Box<EvaluationFailure>> {
    let input = format!(
        "<Invoice xmlns='{}' xmlns:cac='{}' xmlns:cbc='{}'>{body}</Invoice>",
        xml::UBL,
        xml::CAC,
        xml::CBC
    );
    let context = EvaluationContext {
        instant: "2026-09-23T12:00:00+03:00".parse().unwrap(),
        limits: Limits::default(),
    };
    let prefix = format!("cen:{site:03}:");
    assert!(
        metadata::RULES.iter().any(|r| r.site.starts_with(&prefix)),
        "missing {prefix}"
    );
    evaluate_matching(&input, &context, |r| r.site.starts_with(&prefix))
        .map(|report| report.stages[0].findings.len())
}
fn total(fields: &str) -> String {
    format!("<cac:LegalMonetaryTotal>{fields}</cac:LegalMonetaryTotal>")
}
fn adjustment(charge: bool, amount: &str) -> String {
    format!(
        "<cac:AllowanceCharge><cbc:ChargeIndicator>{charge}</cbc:ChargeIndicator><cbc:Amount>{amount}</cbc:Amount></cac:AllowanceCharge>"
    )
}

#[test]
fn allowance_and_charge_sums_are_exact_and_scope_to_total_siblings() {
    for (site, charge, field) in [
        (17, false, "AllowanceTotalAmount"),
        (19, true, "ChargeTotalAmount"),
    ] {
        for (value, errors) in [("0.30", 0), ("0.29", 1)] {
            let body = total(&format!("<cbc:{field}>{value}</cbc:{field}>"))
                + &adjustment(charge, "0.1")
                + &adjustment(charge, "0.2");
            assert_eq!(check(site, &body).unwrap(), errors);
        }
        assert_eq!(check(site, &total("")).unwrap(), 0);
        assert_eq!(
            check(site, &(total("") + &adjustment(charge, "1"))).unwrap(),
            1
        );
        assert_eq!(
            check(site, &total(&format!("<cbc:{field}>0</cbc:{field}>"))).unwrap(),
            0
        );
        assert_eq!(
            check(
                site,
                &(total(&format!("<cbc:{field}>-1.00</cbc:{field}>"))
                    + &adjustment(charge, "-1.005"))
            )
            .unwrap(),
            0
        );
        assert_eq!(
            check(
                site,
                &(total(&format!("<cbc:{field}>0.30</cbc:{field}>"))
                    + &format!(
                        "<cac:InvoiceLine>{}</cac:InvoiceLine>",
                        adjustment(charge, "0.3")
                    ))
            )
            .unwrap(),
            1
        );
    }
}

#[test]
fn empty_charge_totals_follow_alternate_sites_without_casting() {
    for value in ["", " \t "] {
        let body = total(&format!(
            "<cbc:ChargeTotalAmount>{value}</cbc:ChargeTotalAmount><cbc:TaxExclusiveAmount>bad</cbc:TaxExclusiveAmount>"
        ));
        assert_eq!(check(18, &body).unwrap(), 1);
        assert_eq!(check(20, &body).unwrap(), 1);
        assert_eq!(check(19, &body).unwrap(), 0);
        assert_eq!(check(21, &body).unwrap(), 0);
    }
    for site in [18, 20] {
        assert_eq!(check(site, &total("")).unwrap(), 0);
        assert_eq!(
            check(
                site,
                &total("<cbc:ChargeTotalAmount>0</cbc:ChargeTotalAmount>")
            )
            .unwrap(),
            0
        );
    }
    let body = total(
        "<cbc:ChargeTotalAmount>0</cbc:ChargeTotalAmount><cbc:ChargeTotalAmount>0</cbc:ChargeTotalAmount>",
    );
    assert_eq!(check(18, &body).unwrap_err().kind, FailureKind::Cardinality);
}

#[test]
fn exclusive_total_branches_preserve_raw_node_sum_and_local_no_adjustment_case() {
    for (fields, exclusive) in [
        ("<cbc:ChargeTotalAmount>3</cbc:ChargeTotalAmount>", "103"),
        (
            "<cbc:AllowanceTotalAmount>7</cbc:AllowanceTotalAmount>",
            "93",
        ),
        (
            "<cbc:ChargeTotalAmount>3</cbc:ChargeTotalAmount><cbc:AllowanceTotalAmount>7</cbc:AllowanceTotalAmount>",
            "96",
        ),
        ("", "42"),
    ] {
        let body = total(&format!(
            "<cbc:LineExtensionAmount>42</cbc:LineExtensionAmount><cbc:TaxExclusiveAmount>{exclusive}</cbc:TaxExclusiveAmount>{fields}"
        )) + "<cac:InvoiceLine><cbc:LineExtensionAmount>100</cbc:LineExtensionAmount></cac:InvoiceLine>";
        assert_eq!(check(21, &body).unwrap(), 0);
        assert_eq!(
            check(
                21,
                &body.replace(
                    &format!(">{exclusive}</cbc:TaxExclusiveAmount>"),
                    ">999</cbc:TaxExclusiveAmount>"
                )
            )
            .unwrap(),
            1
        );
    }
    // sum(untyped nodes) permits repeated amounts; xs:decimal(field) does not.
    let body = total(
        "<cbc:TaxExclusiveAmount>4</cbc:TaxExclusiveAmount><cbc:ChargeTotalAmount>1</cbc:ChargeTotalAmount>",
    ) + "<cac:InvoiceLine><cbc:LineExtensionAmount>1</cbc:LineExtensionAmount><cbc:LineExtensionAmount>2</cbc:LineExtensionAmount></cac:InvoiceLine>";
    assert_eq!(check(21, &body).unwrap(), 0);
}

#[test]
fn payable_reconciliation_rounds_each_source_operand_at_its_own_step() {
    for (fields, payable) in [
        ("", "100.005"),
        ("<cbc:PrepaidAmount>1</cbc:PrepaidAmount>", "99.01"),
        (
            "<cbc:PayableRoundingAmount>0.005</cbc:PayableRoundingAmount>",
            "100.01",
        ),
        (
            "<cbc:PrepaidAmount>1</cbc:PrepaidAmount><cbc:PayableRoundingAmount>0.01</cbc:PayableRoundingAmount>",
            "99.02",
        ),
    ] {
        let body = total(&format!(
            "<cbc:TaxInclusiveAmount>100.005</cbc:TaxInclusiveAmount><cbc:PayableAmount>{payable}</cbc:PayableAmount>{fields}"
        ));
        let expected = usize::from(fields.contains("0.005")); // rounded payable-minus-rounding cannot equal unrounded inclusive.
        assert_eq!(check(22, &body).unwrap(), expected, "{fields}");
        assert_eq!(
            check(
                22,
                &body.replace(
                    &format!(">{payable}</cbc:PayableAmount>"),
                    ">999</cbc:PayableAmount>"
                )
            )
            .unwrap(),
            1
        );
    }
    assert_eq!(check(22, &total("<cbc:TaxInclusiveAmount>100</cbc:TaxInclusiveAmount><cbc:PayableAmount>100.01</cbc:PayableAmount><cbc:PayableRoundingAmount>0.01</cbc:PayableRoundingAmount>")).unwrap(), 0);
}
