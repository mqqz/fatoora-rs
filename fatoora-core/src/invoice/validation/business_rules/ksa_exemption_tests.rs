use super::{
    FailureKind, Limits,
    ksa_exemptions::KsaExemptionCheck as K,
    xml::{CAC, CBC, CREDIT_NOTE, UBL, XmlView},
};

fn view(namespace: &str, body: &str) -> XmlView {
    XmlView::parse(
        &format!("<Invoice xmlns='{namespace}' xmlns:cac='{CAC}' xmlns:cbc='{CBC}' xmlns:other='urn:other'>{body}</Invoice>"),
        &Limits::default(),
    )
    .unwrap()
}

fn run(check: K, xml: &XmlView) -> Result<Vec<bool>, FailureKind> {
    check
        .contexts(xml)?
        .into_iter()
        .map(|node| check.passes(xml, node, 4096))
        .collect()
}

fn check(check: K, body: &str) -> Result<Vec<bool>, FailureKind> {
    run(check, &view(UBL, body))
}

fn category(code: &str, body: &str) -> String {
    format!("<cac:TaxCategory><cbc:ID>{code}</cbc:ID>{body}</cac:TaxCategory>")
}

fn vat_category(code: &str, body: &str) -> String {
    category(
        code,
        &format!("{body}<cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>"),
    )
}

fn breakdown(category: &str) -> String {
    format!("<cac:TaxTotal><cac:TaxSubtotal>{category}</cac:TaxSubtotal></cac:TaxTotal>")
}

fn prepayment(category: &str) -> String {
    format!("<cac:InvoiceLine>{}</cac:InvoiceLine>", breakdown(category))
}

fn trigger() -> String {
    breakdown(&vat_category("S", ""))
}

#[test]
fn category_code_061_preserves_raw_substring_match_and_all_four_root_paths() {
    for (value, expected) in [
        ("S", true),
        ("Z", true),
        ("E", true),
        ("O", true),
        ("", true),
        (" ", true),
        ("S Z", true),
        (" S ", true),
        ("S Z E O", true),
        ("s", false),
        ("\tS", false),
        ("\u{a0}S", false),
        ("SS", false),
    ] {
        let c = category(value, "");
        let item = c.replace("TaxCategory", "ClassifiedTaxCategory");
        let body = format!(
            "{}{}<cac:AllowanceCharge>{c}</cac:AllowanceCharge><cac:InvoiceLine><cac:Item>{item}</cac:Item></cac:InvoiceLine>",
            breakdown(&c),
            prepayment(&c)
        );
        assert_eq!(
            check(K::VatCategoryCode, &body),
            Ok(vec![expected; 4]),
            "{value:?}"
        );
    }
    let invalid = breakdown(&category("BAD", ""));
    assert_eq!(
        run(K::VatCategoryCode, &view(CREDIT_NOTE, &invalid)),
        Ok(vec![])
    );
    assert_eq!(
        check(
            K::VatCategoryCode,
            &format!("<cac:Wrapper><Invoice xmlns='{UBL}'>{invalid}</Invoice></cac:Wrapper>")
        ),
        Ok(vec![])
    );
    assert_eq!(
        check(
            K::VatCategoryCode,
            "<cac:TaxCategory><cbc:ID>BAD</cbc:ID></cac:TaxCategory>"
        ),
        Ok(vec![])
    );
}

#[test]
fn reason_length_062_uses_any_root_raw_codepoint_length_and_no_vat_gate() {
    for code in ["Z", " E ", "O"] {
        for (text, expected) in [
            (None, true),
            (Some("".to_owned()), false),
            (Some(" ".to_owned()), true),
            (Some("ع".repeat(1000)), true),
            (Some("💰".repeat(1001)), false),
        ] {
            let text = text.map_or_else(String::new, |v| {
                format!("<cbc:TaxExemptionReason>{v}</cbc:TaxExemptionReason>")
            });
            let body = breakdown(&category(code, &text));
            assert_eq!(
                run(K::ExemptionReasonLength, &view("urn:other", &body)),
                Ok(vec![expected])
            );
        }
    }
    assert_eq!(
        check(
            K::ExemptionReasonLength,
            &breakdown(&category("S", "<cbc:TaxExemptionReason/>"))
        ),
        Ok(vec![])
    );
    assert_eq!(
        check(
            K::ExemptionReasonLength,
            &prepayment(&category("Z", "<cbc:TaxExemptionReason/>"))
        ),
        Ok(vec![])
    );
    assert_eq!(
        check(
            K::ExemptionReasonLength,
            &breakdown(&category("Z", "<cbc:ID>E</cbc:ID>"))
        ),
        Err(FailureKind::Cardinality)
    );
    assert_eq!(
        check(
            K::ExemptionReasonLength,
            &breakdown(&category(
                "Z",
                "<cbc:TaxExemptionReason>x</cbc:TaxExemptionReason><cbc:TaxExemptionReason>y</cbc:TaxExemptionReason>"
            ))
        ),
        Err(FailureKind::Cardinality)
    );
}

#[test]
fn mime_113_uses_pinned_tokens_normalized_xml_space_and_exact_namespace() {
    for (mime, expected) in [
        (Some("text/plain"), true),
        (Some(" text/csv "), true),
        (Some("application/pdf"), true),
        (Some("image/png"), true),
        (Some("image/jpeg"), true),
        (Some("image/tiff"), true),
        (Some("application/acad"), true),
        (Some("application/dwg"), true),
        (Some("drawing/dwg"), true),
        (
            Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            true,
        ),
        (Some("application/vnd.oasis.opendocument.spreadsheet"), true),
        (None, false),
        (Some(""), false),
        (Some("text/pla"), false),
        (Some("Text/plain"), false),
        (Some("text/plain image/png"), false),
        (Some("\u{a0}text/plain"), false),
    ] {
        let attr = mime.map_or_else(String::new, |m| format!(" mimeCode='{m}'"));
        let body = format!(
            "<cac:AdditionalDocumentReference><cac:Attachment><cbc:EmbeddedDocumentBinaryObject{attr}/></cac:Attachment></cac:AdditionalDocumentReference>"
        );
        assert_eq!(
            run(K::MimeCode, &view("urn:other", &body)),
            Ok(vec![expected]),
            "{mime:?}"
        );
    }
    assert_eq!(
        check(
            K::MimeCode,
            "<cac:Attachment><cbc:EmbeddedDocumentBinaryObject/></cac:Attachment>"
        ),
        Ok(vec![])
    );
    assert_eq!(
        check(
            K::MimeCode,
            "<cac:AdditionalDocumentReference><cac:Attachment><cbc:EmbeddedDocumentBinaryObject other:mimeCode='text/plain'/></cac:Attachment></cac:AdditionalDocumentReference>"
        ),
        Ok(vec![false])
    );
}

#[test]
fn reason_114_and_126_are_required_only_when_code_exists() {
    for (suffix, expected) in [
        ("", true),
        ("<cbc:TaxExemptionReasonCode/>", false),
        (
            "<cbc:TaxExemptionReasonCode>X</cbc:TaxExemptionReasonCode><cbc:TaxExemptionReason> \t\n </cbc:TaxExemptionReason>",
            false,
        ),
        (
            "<cbc:TaxExemptionReasonCode/><cbc:TaxExemptionReason>reason</cbc:TaxExemptionReason>",
            true,
        ),
        (
            "<cbc:TaxExemptionReasonCode/><cbc:TaxExemptionReason>\u{a0}</cbc:TaxExemptionReason>",
            true,
        ),
    ] {
        assert_eq!(
            check(K::ExemptionReason, &breakdown(&category("Z", suffix))),
            Ok(vec![expected])
        );
        assert_eq!(
            check(
                K::PrepaymentExemptionReason,
                &format!("{}{}", trigger(), prepayment(&vat_category("E", suffix)))
            ),
            Ok(vec![expected])
        );
    }
    let duplicate = "<cbc:TaxExemptionReason>x</cbc:TaxExemptionReason><cbc:TaxExemptionReason>y</cbc:TaxExemptionReason>";
    assert_eq!(
        check(K::ExemptionReason, &breakdown(&category("O", duplicate))),
        Ok(vec![true])
    );
    assert_eq!(
        check(
            K::ExemptionReason,
            &breakdown(&category(
                "O",
                &format!("<cbc:TaxExemptionReasonCode/>{duplicate}")
            ))
        ),
        Err(FailureKind::Cardinality)
    );
}

#[test]
fn code_lists_115_and_127_preserve_missing_empty_and_distinct_zero_lists() {
    for (category_code, code, expected) in [
        ("Z", "VATEX-SA-32", true),
        ("Z", "VATEX-SA-34-5", true),
        ("Z", "VATEX-SA-DUTYFREE", true),
        ("E", "VATEX-SA-29-7", true),
        ("E", "VATEX-SA-30", true),
        ("O", "VATEX-SA-OOS", true),
        ("Z", " VATEX-SA-EDU ", true),
        ("Z", "", true),
        ("Z", "  ", true),
        ("Z", "VATEX-SA-29", false),
        ("E", "VATEX-SA-32", false),
        ("O", "VAT-OOS-SA", false),
        ("Z", "vatex-sa-32", false),
        ("Z", "VATEX-SA-3", false),
        ("Z", "VATEX-SA-32 VATEX-SA-33", false),
    ] {
        let suffix = format!("<cbc:TaxExemptionReasonCode>{code}</cbc:TaxExemptionReasonCode>");
        assert_eq!(
            check(
                K::ExemptionCode,
                &breakdown(&category(category_code, &suffix))
            ),
            Ok(vec![expected]),
            "{category_code}/{code}"
        );
        assert_eq!(
            check(
                K::PrepaymentExemptionCode,
                &format!(
                    "{}{}",
                    trigger(),
                    prepayment(&vat_category(category_code, &suffix))
                )
            ),
            Ok(vec![expected]),
            "{category_code}/{code}"
        );
    }
    for code in ["VATEX-SA-ROYALDECREE", "VATEX-SA-32(bis)"] {
        let suffix = format!("<cbc:TaxExemptionReasonCode>{code}</cbc:TaxExemptionReasonCode>");
        assert_eq!(
            check(K::ExemptionCode, &breakdown(&category("Z", &suffix))),
            Ok(vec![true])
        );
        assert_eq!(
            check(
                K::PrepaymentExemptionCode,
                &format!("{}{}", trigger(), prepayment(&vat_category("Z", &suffix)))
            ),
            Ok(vec![false])
        );
    }
    for code in ["Z", "E", "O"] {
        assert_eq!(
            check(K::ExemptionCode, &breakdown(&category(code, ""))),
            Ok(vec![true])
        );
    }
    assert_eq!(
        check(
            K::ExemptionCode,
            &breakdown(&category(
                "Z",
                "<cbc:TaxExemptionReasonCode/><cbc:TaxExemptionReasonCode/>"
            ))
        ),
        Err(FailureKind::Cardinality)
    );
}

#[test]
fn required_codes_116_118_and_123_125_use_raw_presence_then_normalized_nonempty() {
    for (document_check, prepay_check, category_code) in [
        (K::OutsideScopeCode, K::PrepaymentOutsideScopeCode, "O"),
        (K::ExemptCode, K::PrepaymentExemptCode, "E"),
        (K::ZeroRatedCode, K::PrepaymentZeroRatedCode, "Z"),
    ] {
        for (suffix, expected) in [
            ("", false),
            ("<cbc:TaxExemptionReasonCode/>", false),
            (
                "<cbc:TaxExemptionReasonCode> \t </cbc:TaxExemptionReasonCode>",
                false,
            ),
            (
                "<cbc:TaxExemptionReasonCode>anything</cbc:TaxExemptionReasonCode>",
                true,
            ),
            (
                "<cbc:TaxExemptionReasonCode>\u{a0}</cbc:TaxExemptionReasonCode>",
                true,
            ),
        ] {
            assert_eq!(
                check(document_check, &breakdown(&category(category_code, suffix))),
                Ok(vec![expected])
            );
            assert_eq!(
                check(
                    prepay_check,
                    &format!(
                        "{}{}",
                        trigger(),
                        prepayment(&vat_category(category_code, suffix))
                    )
                ),
                Ok(vec![expected])
            );
        }
        assert_eq!(
            check(
                document_check,
                &breakdown(&category(if category_code == "Z" { "E" } else { "Z" }, ""))
            ),
            Ok(vec![true])
        );
        assert_eq!(
            check(
                prepay_check,
                &format!(
                    "{}{}",
                    trigger(),
                    prepayment(&vat_category(
                        category_code,
                        "<cbc:TaxExemptionReasonCode/><cbc:TaxExemptionReasonCode/>"
                    ))
                )
            ),
            Err(FailureKind::Cardinality)
        );
    }
}

#[test]
fn document_exemptions_114_118_match_nested_invoices_but_not_credit_note() {
    let invalid = breakdown(&category("Z", ""));
    assert_eq!(
        check(
            K::ZeroRatedCode,
            &format!("<cac:Wrapper><Invoice xmlns='{UBL}'>{invalid}</Invoice></cac:Wrapper>")
        ),
        Ok(vec![false])
    );
    assert_eq!(
        run(K::ZeroRatedCode, &view(CREDIT_NOTE, &invalid)),
        Ok(vec![])
    );
    assert_eq!(
        check(
            K::ZeroRatedCode,
            &breakdown(&category(" Z ", "<cbc:ID>Z</cbc:ID>"))
        ),
        Err(FailureKind::Cardinality)
    );
}

fn standard_body(kind: K, percent: &str) -> String {
    let c = vat_category("S", percent);
    match kind {
        K::AllowanceStandardRate => format!(
            "<cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator>{c}</cac:AllowanceCharge>"
        ),
        K::BreakdownStandardRate => breakdown(&c),
        K::ItemStandardRate => format!(
            "<cac:InvoiceLine><cac:Item>{}</cac:Item></cac:InvoiceLine>",
            c.replace("TaxCategory", "ClassifiedTaxCategory")
        ),
        K::PrepaymentStandardRate => prepayment(&c),
        _ => unreachable!(),
    }
}

#[test]
fn standard_rates_119_122_follow_floor_and_boolean_number_source_quirk() {
    for kind in [
        K::AllowanceStandardRate,
        K::BreakdownStandardRate,
        K::ItemStandardRate,
        K::PrepaymentStandardRate,
    ] {
        for (value, expected) in [
            ("5", true),
            ("5.00", true),
            ("5e0", true),
            ("15", true),
            ("15.999", true),
            (" 15.1 ", true),
            ("4.999", false),
            ("5.1", false),
            ("14.999", false),
            ("16", false),
            ("-5", false),
            ("INF", false),
            ("NaN", false),
        ] {
            let body = standard_body(kind, &format!("<cbc:Percent>{value}</cbc:Percent>"));
            assert_eq!(check(kind, &body), Ok(vec![expected]), "{kind:?}/{value}");
        }
        assert_eq!(check(kind, &standard_body(kind, "")), Ok(vec![true]));
        assert_eq!(
            check(
                kind,
                &standard_body(kind, "<cbc:Percent>bogus</cbc:Percent>")
            ),
            Err(FailureKind::InvalidDouble)
        );
        assert_eq!(
            check(kind, &standard_body(kind, "<cbc:Percent/>")),
            Err(FailureKind::InvalidDouble)
        );
        assert_eq!(
            check(
                kind,
                &standard_body(
                    kind,
                    "<cbc:Percent>15</cbc:Percent><cbc:Percent>5</cbc:Percent>"
                )
            ),
            Err(FailureKind::Cardinality)
        );
    }
}

#[test]
fn prepayment_length_128_has_optional_raw_unicode_length() {
    for (text, expected) in [
        (None, true),
        (Some("".to_owned()), false),
        (Some(" ".to_owned()), true),
        (Some("💰".repeat(1000)), true),
        (Some("ع".repeat(1001)), false),
    ] {
        let suffix = text.map_or_else(String::new, |t| {
            format!("<cbc:TaxExemptionReason>{t}</cbc:TaxExemptionReason>")
        });
        assert_eq!(
            check(
                K::PrepaymentExemptionReasonLength,
                &format!("{}{}", trigger(), prepayment(&vat_category("O", &suffix)))
            ),
            Ok(vec![expected])
        );
    }
    assert_eq!(
        check(
            K::PrepaymentExemptionReasonLength,
            &format!(
                "{}{}",
                trigger(),
                prepayment(&vat_category(
                    "O",
                    "<cbc:TaxExemptionReason/><cbc:TaxExemptionReason/>"
                ))
            )
        ),
        Err(FailureKind::Cardinality)
    );
}

#[test]
fn template039_requires_outer_standard_vat_context_and_retains_inner_location() {
    let inner = prepayment(&vat_category("Z", ""));
    assert_eq!(check(K::PrepaymentZeroRatedCode, &inner), Ok(vec![]));
    let xml = view(UBL, &format!("{}{}{inner}", trigger(), trigger()));
    let contexts = K::PrepaymentZeroRatedCode.contexts(&xml).unwrap();
    assert_eq!(contexts.len(), 2);
    assert_eq!(contexts[0], contexts[1]);
    assert!(
        xml.node(contexts[0])
            .location
            .contains("local-name()='InvoiceLine'")
    );
    assert!(xml.node(contexts[0]).location.ends_with("local-name()='TaxCategory' and namespace-uri()='urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2'][1]"));
    assert_eq!(
        run(K::PrepaymentZeroRatedCode, &xml),
        Ok(vec![false, false])
    );
    // A prepayment S node matches two union arms, but fires only once.
    assert_eq!(
        check(
            K::PrepaymentZeroRatedCode,
            &format!("{}{inner}", prepayment(&vat_category("S", "")))
        ),
        Ok(vec![false])
    );
    // An outer context may be nested; its inner for-each remains root-anchored.
    assert_eq!(
        check(
            K::PrepaymentZeroRatedCode,
            &format!("<cac:Wrapper>{}</cac:Wrapper>{inner}", trigger())
        ),
        Ok(vec![false])
    );
    assert_eq!(
        check(
            K::PrepaymentZeroRatedCode,
            &format!("{}<cac:Wrapper>{inner}</cac:Wrapper>", trigger())
        ),
        Ok(vec![])
    );
}

#[test]
fn template039_preserves_match_guard_errors_and_missing_indicator_behavior() {
    let inner = prepayment(&vat_category("Z", ""));
    for indicator in ["false", "true", "0", "1", " true "] {
        let outer = format!(
            "<cac:AllowanceCharge><cbc:ChargeIndicator>{indicator}</cbc:ChargeIndicator>{}</cac:AllowanceCharge>",
            vat_category(" S ", "")
        );
        assert_eq!(
            check(K::PrepaymentZeroRatedCode, &format!("{outer}{inner}")),
            Ok(vec![false])
        );
    }
    let missing_indicator = format!(
        "<cac:AllowanceCharge>{}</cac:AllowanceCharge>",
        vat_category("S", "<cbc:Percent>6</cbc:Percent>")
    );
    assert_eq!(
        check(K::AllowanceStandardRate, &missing_indicator),
        Ok(vec![])
    );
    assert_eq!(
        check(
            K::AllowanceStandardRate,
            &format!("{}{missing_indicator}", trigger())
        ),
        Ok(vec![false])
    );
    for (outer, failure) in [
        (
            format!(
                "<cac:AllowanceCharge><cbc:ChargeIndicator>FALSE</cbc:ChargeIndicator>{}</cac:AllowanceCharge>",
                vat_category("S", "")
            ),
            FailureKind::InvalidBoolean,
        ),
        (
            breakdown(&vat_category("S", "<cbc:ID>S</cbc:ID>")),
            FailureKind::Cardinality,
        ),
        (
            breakdown(&category(
                "S",
                "<cac:TaxScheme><cbc:ID>VAT</cbc:ID><cbc:ID>VAT</cbc:ID></cac:TaxScheme>",
            )),
            FailureKind::Cardinality,
        ),
    ] {
        // Guard errors survive even when the global inner loop is empty.
        assert_eq!(check(K::PrepaymentZeroRatedCode, &outer), Err(failure));
    }
    for outer in [
        breakdown(&category("S", "")),
        breakdown(&category(
            "S",
            "<cac:TaxScheme><cbc:ID>OTHER</cbc:ID></cac:TaxScheme>",
        )),
    ] {
        assert_eq!(
            check(K::PrepaymentZeroRatedCode, &format!("{outer}{inner}")),
            Ok(vec![])
        );
    }
    let outer = breakdown(&category(
        "S",
        "<cac:TaxScheme><cbc:ID> vat </cbc:ID></cac:TaxScheme>",
    ));
    assert_eq!(
        check(K::PrepaymentZeroRatedCode, &format!("{outer}{inner}")),
        Ok(vec![false])
    );
}

#[test]
fn template039_inner_selection_preserves_category_and_tax_scheme_cardinality() {
    for inner in [
        prepayment(&vat_category("Z", "<cbc:ID>Z</cbc:ID>")),
        prepayment(&category(
            "Z",
            "<cac:TaxScheme><cbc:ID>VAT</cbc:ID><cbc:ID>VAT</cbc:ID></cac:TaxScheme>",
        )),
    ] {
        assert_eq!(
            check(K::PrepaymentZeroRatedCode, &format!("{}{inner}", trigger())),
            Err(FailureKind::Cardinality)
        );
    }
    assert_eq!(
        check(
            K::PrepaymentZeroRatedCode,
            &format!("{}{}", trigger(), prepayment(&category("Z", "")))
        ),
        Ok(vec![])
    );
}

#[test]
fn template039_checks_cartesian_capacity_before_materializing_occurrences() {
    let xml = view(UBL, &trigger().repeat(317));
    assert_eq!(
        K::BreakdownStandardRate.contexts(&xml),
        Err(FailureKind::Limit("rule context occurrences"))
    );
}
