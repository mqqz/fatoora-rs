use super::{
    FailureKind, Limits,
    ksa_prepayment::KsaPrepaymentCheck as K,
    xml::{CAC, CBC, CREDIT_NOTE, UBL, XmlView},
};

fn view(namespace: &str, body: &str) -> XmlView {
    let name = if namespace == CREDIT_NOTE {
        "CreditNote"
    } else {
        "Invoice"
    };
    XmlView::parse(
        &format!("<{name} xmlns='{namespace}' xmlns:cac='{CAC}' xmlns:cbc='{CBC}'>{body}</{name}>"),
        &Limits::default(),
    )
    .unwrap()
}

fn run(check: K, body: &str) -> Result<Vec<bool>, FailureKind> {
    let xml = view(UBL, body);
    check
        .contexts(&xml)?
        .into_iter()
        .map(|node| check.passes(&xml, node, 4096))
        .collect()
}

fn paid(value: &str) -> String {
    format!(
        "<cac:LegalMonetaryTotal><cbc:PrepaidAmount>{value}</cbc:PrepaidAmount></cac:LegalMonetaryTotal>"
    )
}

fn reference(code: &str) -> String {
    format!(
        "<cac:DocumentReference><cbc:ID/><cbc:IssueDate/><cbc:IssueTime/>{code}</cac:DocumentReference>"
    )
}

fn line(contents: &str) -> String {
    format!("<cac:InvoiceLine>{contents}</cac:InvoiceLine>")
}

fn subtotal(taxable: &str, tax: &str, code: &str, percent: &str, scheme: &str) -> String {
    format!(
        "<cac:TaxTotal><cac:TaxSubtotal>{taxable}{tax}<cac:TaxCategory><cbc:ID>{code}</cbc:ID>{percent}<cac:TaxScheme><cbc:ID>{scheme}</cbc:ID></cac:TaxScheme></cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal>"
    )
}

fn amounts(taxable: &str, tax: &str, code: &str, percent: &str) -> String {
    subtotal(
        &format!("<cbc:TaxableAmount>{taxable}</cbc:TaxableAmount>"),
        &format!("<cbc:TaxAmount>{tax}</cbc:TaxAmount>"),
        code,
        &format!("<cbc:Percent>{percent}</cbc:Percent>"),
        "VAT",
    )
}

#[test]
fn total_017_combines_raw_double_sums_with_decimal_prepaid_rounding() {
    assert_eq!(run(K::Total, ""), Ok(vec![true]));
    assert_eq!(
        run(K::Total, &line(&amounts("0", "0", "S", "15"))),
        Ok(vec![false])
    );
    for (prepaid, taxable, tax, code, expected) in [
        ("115", "100", "15", "386", true),
        ("115.004", "100", "15", "386", true),
        ("115.006", "100", "15", "386", false),
        ("115", "100", "15", " 386 ", false),
        ("100", "100", "0", "383", true),
        ("0", "0", "0", "386", false),
        ("-115", "-100", "-15", "383", true),
        ("2.675", "2.675", "0", "386", true),
    ] {
        let body = format!(
            "{}{}",
            paid(prepaid),
            line(&format!(
                "{}{}",
                reference(&format!(
                    "<cbc:DocumentTypeCode>{code}</cbc:DocumentTypeCode>"
                )),
                amounts(taxable, tax, "S", "15")
            ))
        );
        assert_eq!(
            run(K::Total, &body),
            Ok(vec![expected]),
            "{prepaid}/{taxable}/{tax}/{code}"
        );
    }
    assert_eq!(
        run(K::Total, &paid("NaN")),
        Err(FailureKind::InvalidDecimal)
    );
    assert_eq!(
        run(K::Total, &format!("{}{}", paid("1"), paid("1"))),
        Err(FailureKind::Cardinality)
    );
    let xml = view(
        CREDIT_NOTE,
        &format!("{}{}", paid("115"), line(&amounts("100", "99", "S", "15"))),
    );
    assert_eq!(K::Total.contexts(&xml), Ok(vec![0]));
    assert_eq!(K::Total.passes(&xml, 0, 4096), Ok(true));
}

#[test]
fn prepayment_contexts_use_root_invoice_positive_general_comparison() {
    for (prepaid, active) in [
        ("1", true),
        ("1E1", true),
        ("INF", true),
        ("0", false),
        ("-1", false),
        ("NaN", false),
    ] {
        let body = format!(
            "{}{}",
            paid(prepaid),
            line(&amounts("100", "15", "S", "15"))
        );
        assert_eq!(
            run(K::ActiveStandardTax, &body).unwrap().len(),
            usize::from(active)
        );
        assert_eq!(
            run(K::InactiveStandardTax, &body).unwrap().len(),
            usize::from(!active)
        );
    }
    assert_eq!(
        run(
            K::ActiveStandardTax,
            &format!("{}{}", paid("bad"), line(""))
        ),
        Err(FailureKind::InvalidDouble)
    );
    let xml = view(
        CREDIT_NOTE,
        &format!("{}{}", paid("1"), line(&amounts("100", "15", "S", "15"))),
    );
    assert!(K::ActiveStandardTax.contexts(&xml).unwrap().is_empty());
    let nested = format!(
        "<cac:Wrapper><Invoice xmlns='{UBL}'>{}{}</Invoice></cac:Wrapper>",
        paid("1"),
        line(&amounts("100", "15", "S", "15"))
    );
    assert!(run(K::ActiveStandardTax, &nested).unwrap().is_empty());
    let hidden = format!(
        "<cac:LegalMonetaryTotal><cbc:PrepaidAmount>1</cbc:PrepaidAmount>{}</cac:LegalMonetaryTotal>",
        line(&amounts("100", "15", "S", "15"))
    );
    assert!(run(K::ActiveStandardTax, &hidden).unwrap().is_empty());
}

#[test]
fn zero_tax_branches_require_both_formatted_comparisons_and_preserve_empty_operands() {
    for (code, percent, tax, expected) in [
        ("Z", "0", "0", true),
        ("E", "0", "0.004", true),
        ("E", "0", "0.006", false),
        ("Z", "5", "0", false),
        ("Z", "5", "5", false),
        ("S", "0", "9", true),
    ] {
        let content = line(&amounts("100", tax, code, percent));
        assert_eq!(run(K::InactiveZeroTax, &content), Ok(vec![expected]));
        assert_eq!(
            run(K::ActiveZeroTax, &format!("{}{content}", paid("1"))),
            Ok(vec![expected])
        );
    }
    let missing_rate = line(&subtotal(
        "<cbc:TaxableAmount>100</cbc:TaxableAmount>",
        "<cbc:TaxAmount>0</cbc:TaxAmount>",
        "O",
        "",
        "VAT",
    ));
    assert_eq!(run(K::InactiveZeroTax, &missing_rate), Ok(vec![false]));
    let absent_values = line(&subtotal("", "", "O", "", "VAT"));
    assert_eq!(run(K::InactiveZeroTax, &absent_values), Ok(vec![true]));
    let empty = line(&amounts("100", "0", "O", ""));
    assert_eq!(
        run(K::InactiveZeroTax, &empty),
        Err(FailureKind::InvalidDecimal)
    );
    let invalid = line(&amounts("bad", "0", "Z", "0"));
    assert_eq!(
        run(K::InactiveZeroTax, &invalid),
        Err(FailureKind::InvalidDecimal)
    );
}

#[test]
fn standard_tax_branches_allow_one_cent_and_require_vat_scheme_for_rate() {
    for (tax, expected) in [
        ("14.99", true),
        ("15", true),
        ("15.01", true),
        ("14.98", false),
        ("15.02", false),
    ] {
        let content = line(&amounts("100", tax, "S", "15"));
        assert_eq!(run(K::InactiveStandardTax, &content), Ok(vec![expected]));
        assert_eq!(
            run(K::ActiveStandardTax, &format!("{}{content}", paid("1"))),
            Ok(vec![expected])
        );
    }
    let missing_rate = line(&subtotal(
        "<cbc:TaxableAmount>100</cbc:TaxableAmount>",
        "<cbc:TaxAmount>0</cbc:TaxAmount>",
        "S",
        "",
        "VAT",
    ));
    assert_eq!(run(K::InactiveStandardTax, &missing_rate), Ok(vec![false]));
    let non_vat = line(&subtotal(
        "<cbc:TaxableAmount>100</cbc:TaxableAmount>",
        "<cbc:TaxAmount>15</cbc:TaxAmount>",
        "S",
        "<cbc:Percent>15</cbc:Percent>",
        "OTHER",
    ));
    assert_eq!(run(K::InactiveStandardTax, &non_vat), Ok(vec![false]));
    let normalized = non_vat.replace("OTHER", " vat ");
    assert_eq!(run(K::InactiveStandardTax, &normalized), Ok(vec![true]));
    let missing_both = line(&subtotal(
        "",
        "",
        "S",
        "<cbc:Percent>15</cbc:Percent>",
        "OTHER",
    ));
    assert_eq!(run(K::InactiveStandardTax, &missing_both), Ok(vec![true]));
    let duplicate = line(&amounts("100", "15", "S", "15").replace(
        "<cbc:Percent>15</cbc:Percent>",
        "<cbc:Percent>15</cbc:Percent><cbc:Percent>15</cbc:Percent>",
    ));
    assert_eq!(
        run(K::InactiveStandardTax, &duplicate),
        Err(FailureKind::Cardinality)
    );
}

#[test]
fn document_type_branch_distinguishes_raw_386_from_normalized_386_and_missing() {
    for (code, type_pass, zero_pass) in [
        (
            "<cbc:DocumentTypeCode>386</cbc:DocumentTypeCode>",
            true,
            false,
        ),
        (
            "<cbc:DocumentTypeCode> 386 </cbc:DocumentTypeCode>",
            true,
            true,
        ),
        (
            "<cbc:DocumentTypeCode>383</cbc:DocumentTypeCode>",
            false,
            true,
        ),
        ("", true, false),
    ] {
        let body = format!("{}{}", paid("1"), line(&reference(code)));
        assert_eq!(run(K::DocumentType, &body), Ok(vec![type_pass]));
        assert_eq!(run(K::ZeroLineAmounts, &body), Ok(vec![zero_pass]));
    }
    let duplicate = format!(
        "{}{}",
        paid("1"),
        line(&reference(
            "<cbc:DocumentTypeCode>383</cbc:DocumentTypeCode><cbc:DocumentTypeCode>386</cbc:DocumentTypeCode>"
        ))
    );
    assert_eq!(
        run(K::DocumentType, &duplicate),
        Err(FailureKind::Cardinality)
    );
}

#[test]
fn zero_line_and_adjustment_amounts_use_general_comparisons() {
    let zeros = "<cbc:LineExtensionAmount>0</cbc:LineExtensionAmount><cac:TaxTotal><cbc:TaxAmount>0.00</cbc:TaxAmount><cbc:RoundingAmount>-0</cbc:RoundingAmount></cac:TaxTotal><cac:Price><cbc:PriceAmount>0e5</cbc:PriceAmount></cac:Price>";
    let refs = format!(
        "{}{}",
        reference("<cbc:DocumentTypeCode>386</cbc:DocumentTypeCode>"),
        reference("")
    );
    let body = format!("{}{}", paid("1"), line(&format!("{refs}{zeros}")));
    assert_eq!(run(K::ZeroLineAmounts, &body), Ok(vec![true, true]));
    assert_eq!(
        run(
            K::ZeroLineAmounts,
            &body.replace(
                "<cbc:PriceAmount>0e5</cbc:PriceAmount>",
                "<cbc:PriceAmount>2</cbc:PriceAmount>"
            )
        ),
        Ok(vec![false, false])
    );
    assert_eq!(
        run(
            K::ZeroLineAmounts,
            &body.replace(
                "<cbc:PriceAmount>0e5</cbc:PriceAmount>",
                "<cbc:PriceAmount>2</cbc:PriceAmount><cbc:PriceAmount>0</cbc:PriceAmount>"
            )
        ),
        Ok(vec![true, true])
    );
    assert_eq!(run(K::ZeroAdjustments, &body), Ok(vec![true, true]));
    for (adjustments, expected) in [
        ("<cac:AllowanceCharge/>", false),
        (
            "<cac:AllowanceCharge><cbc:Amount>1</cbc:Amount></cac:AllowanceCharge>",
            false,
        ),
        (
            "<cac:AllowanceCharge><cbc:Amount>1</cbc:Amount></cac:AllowanceCharge><cac:AllowanceCharge><cbc:Amount>0</cbc:Amount></cac:AllowanceCharge>",
            true,
        ),
    ] {
        let body = format!("{}{}", paid("1"), line(&format!("{refs}{adjustments}")));
        assert_eq!(run(K::ZeroAdjustments, &body), Ok(vec![expected, expected]));
    }
}

#[test]
fn references_023_024_025_use_global_presence_but_local_fields_and_locations() {
    let body = format!("{}{}{}", paid("1"), line(""), line(""));
    assert_eq!(run(K::MissingReferences, &body), Ok(vec![false, false]));
    assert_eq!(run(K::ReferenceFields, &body), Ok(vec![]));
    let references = format!("{}{}", reference("<cbc:DocumentTypeCode/>"), reference(""));
    let body = format!("{}{}{}", paid("1"), line(""), line(&references));
    assert_eq!(run(K::MissingReferences, &body), Ok(vec![]));
    assert_eq!(run(K::ReferenceFields, &body), Ok(vec![true, false]));
    assert_eq!(run(K::SubtotalFields, &body), Ok(vec![false, false]));
    let fields = amounts("", "", "", "");
    let body = format!("{}{}", paid("1"), line(&format!("{references}{fields}")));
    assert_eq!(run(K::SubtotalFields, &body), Ok(vec![true, true]));
    let xml = view(UBL, &body);
    let nodes = K::ReferenceFields.contexts(&xml).unwrap();
    assert!(xml.node(nodes[0]).location.contains("DocumentReference"));
    assert_ne!(xml.node(nodes[0]).location, xml.node(nodes[1]).location);
}

#[test]
fn prepayment_scale_028_counts_raw_lexical_fraction() {
    for (value, expected) in [
        ("1", true),
        ("1.00", true),
        ("1.000", false),
        ("1.0 ", true),
        ("1.00 ", false),
        ("1e3", true),
    ] {
        let body = format!("{}{}", paid("1"), line(&amounts(value, "0", "O", "0")));
        assert_eq!(run(K::AmountScale, &body), Ok(vec![expected]));
    }
    let missing = format!("{}{}", paid("1"), line(&subtotal("", "", "O", "", "VAT")));
    assert_eq!(run(K::AmountScale, &missing), Ok(vec![true]));
}

#[test]
fn prepayment_rates_029_to_031_require_decimal_zero_including_outside_scope() {
    for (check, code) in [
        (K::ZeroRate, "Z"),
        (K::ExemptRate, "E"),
        (K::OutsideRate, "O"),
    ] {
        for (rate, expected) in [
            ("<cbc:Percent>0</cbc:Percent>", Ok(vec![true])),
            ("<cbc:Percent>-0.00</cbc:Percent>", Ok(vec![true])),
            ("<cbc:Percent>1</cbc:Percent>", Ok(vec![false])),
            ("", Ok(vec![false])),
            ("<cbc:Percent/>", Err(FailureKind::InvalidDecimal)),
            (
                "<cbc:Percent>NaN</cbc:Percent>",
                Err(FailureKind::InvalidDecimal),
            ),
        ] {
            let body = format!(
                "{}{}",
                paid("1"),
                line(&subtotal("", "", code, rate, " vat "))
            );
            assert_eq!(run(check, &body), expected);
            assert_eq!(run(check, &body.replace(" vat ", "OTHER")), Ok(vec![true]));
        }
    }
}
