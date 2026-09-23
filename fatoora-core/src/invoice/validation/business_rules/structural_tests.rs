use super::*;

fn check(number: usize, body: &str) -> Result<Vec<RuleFinding>, Box<EvaluationFailure>> {
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
    let prefix = format!("cen:{number:03}:");
    assert!(
        metadata::RULES.iter().any(|r| r.site.starts_with(&prefix)),
        "missing {prefix}"
    );
    evaluate_matching(&input, &context, |r| r.site.starts_with(&prefix))
        .map(|report| report.stages.into_iter().flat_map(|s| s.findings).collect())
}

#[test]
fn required_fields_keep_presence_separate_from_nonempty_values() {
    for (site, prefix, field, suffix, empty_valid) in [
        (
            1,
            "<cac:AdditionalDocumentReference>",
            "cbc:ID",
            "</cac:AdditionalDocumentReference>",
            false,
        ),
        (
            13,
            "<cac:LegalMonetaryTotal>",
            "cbc:TaxExclusiveAmount",
            "</cac:LegalMonetaryTotal>",
            true,
        ),
        (
            14,
            "<cac:LegalMonetaryTotal>",
            "cbc:TaxInclusiveAmount",
            "</cac:LegalMonetaryTotal>",
            true,
        ),
        (
            15,
            "<cac:LegalMonetaryTotal>",
            "cbc:PayableAmount",
            "</cac:LegalMonetaryTotal>",
            true,
        ),
        (31, "", "cbc:ID", "", false),
        (34, "", "cbc:IssueDate", "", false),
        (36, "", "cbc:DocumentCurrencyCode", "", false),
        (
            59,
            "<cac:InvoiceLine>",
            "cbc:ID",
            "</cac:InvoiceLine>",
            false,
        ),
        (
            61,
            "<cac:InvoiceLine>",
            "cbc:LineExtensionAmount",
            "</cac:InvoiceLine>",
            true,
        ),
        (
            63,
            "<cac:InvoiceLine><cac:Price>",
            "cbc:PriceAmount",
            "</cac:Price></cac:InvoiceLine>",
            true,
        ),
        (
            71,
            "<cac:BillingReference><cac:InvoiceDocumentReference>",
            "cbc:ID",
            "</cac:InvoiceDocumentReference></cac:BillingReference>",
            false,
        ),
        (
            72,
            "<cac:AccountingSupplierParty><cac:Party><cac:PostalAddress><cac:Country>",
            "cbc:IdentificationCode",
            "</cac:Country></cac:PostalAddress></cac:Party></cac:AccountingSupplierParty>",
            false,
        ),
        (
            74,
            "<cac:TaxTotal><cac:TaxSubtotal>",
            "cbc:TaxableAmount",
            "</cac:TaxSubtotal></cac:TaxTotal>",
            true,
        ),
        (
            75,
            "<cac:TaxTotal><cac:TaxSubtotal>",
            "cbc:TaxAmount",
            "</cac:TaxSubtotal></cac:TaxTotal>",
            true,
        ),
    ] {
        assert_eq!(
            check(site, &format!("{prefix}{suffix}")).unwrap().len(),
            1,
            "missing {site}"
        );
        assert_eq!(
            check(site, &format!("{prefix}<{field}/>{suffix}"))
                .unwrap()
                .len(),
            usize::from(!empty_valid),
            "empty {site}"
        );
        assert!(
            check(site, &format!("{prefix}<{field}> </{field}>{suffix}"))
                .unwrap()
                .is_empty(),
            "space {site}"
        );
        assert!(
            check(
                site,
                &format!("{prefix}<{field}/><{field}>value</{field}>{suffix}")
            )
            .unwrap()
            .is_empty(),
            "general comparison {site}"
        );
    }
}

#[test]
fn length_checks_use_scalar_unicode_values_and_retain_nested_loop_locations() {
    for (site, prefix, field, suffix, min, max) in [
        (32, "", "cbc:ID", "", 0, 127),
        (
            38,
            "<cac:AccountingSupplierParty><cac:Party><cac:PartyLegalEntity>",
            "cbc:RegistrationName",
            "</cac:PartyLegalEntity></cac:Party></cac:AccountingSupplierParty>",
            1,
            1000,
        ),
        (
            44,
            "<cac:InvoiceLine>",
            "cbc:ID",
            "</cac:InvoiceLine>",
            1,
            6,
        ),
        (
            57,
            "<cac:InvoiceLine><cac:Item>",
            "cbc:Name",
            "</cac:Item></cac:InvoiceLine>",
            3,
            1000,
        ),
    ] {
        assert!(
            check(site, &format!("{prefix}{suffix}"))
                .unwrap()
                .is_empty()
        );
        for length in [0, min, max, max + 1] {
            let body = format!("{prefix}<{field}>{}</{field}>{suffix}", "💰".repeat(length));
            assert_eq!(
                check(site, &body).unwrap().len(),
                usize::from(length < min || length > max),
                "{site}/{length}"
            );
        }
        let error = check(
            site,
            &format!("{prefix}<{field}>x</{field}><{field}>y</{field}>{suffix}"),
        )
        .unwrap_err();
        assert_eq!(error.kind, FailureKind::Cardinality);
    }
    let result = check(44, "<cac:InvoiceLine><cbc:ID>toolong</cbc:ID></cac:InvoiceLine><cac:InvoiceLine><cbc:ID>alsolong</cbc:ID></cac:InvoiceLine>").unwrap();
    assert_eq!(result.len(), 2);
    assert!(result[0].location.contains("'InvoiceLine'") && result[1].location.ends_with("[2]"));
}

#[test]
fn direct_text_comparisons_preserve_comments_and_coalesce_cdata() {
    assert!(
        check(
            33,
            &format!(
                "<cbc:Note>{}<!--split-->{}</cbc:Note>",
                "x".repeat(600),
                "x".repeat(600)
            )
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        check(
            33,
            &format!(
                "<cbc:Note>{}<![CDATA[{}]]></cbc:Note>",
                "x".repeat(600),
                "x".repeat(600)
            )
        )
        .unwrap()
        .len(),
        1
    );
    for (value, violation) in [
        ("0", true),
        ("0.0", false),
        (" 0 ", false),
        ("", false),
        ("0<!--split-->1", true),
        ("0<![CDATA[1]]>", false),
    ] {
        assert_eq!(check(60, &format!("<cac:InvoiceLine><cbc:InvoicedQuantity>{value}</cbc:InvoicedQuantity></cac:InvoiceLine>")).unwrap().len(), usize::from(violation), "{value}");
    }
    assert_eq!(check(60, "<cac:CreditNoteLine><cbc:CreditedQuantity>1</cbc:CreditedQuantity></cac:CreditNoteLine>").unwrap().len(), 1);
}

#[test]
fn allowance_and_charge_contexts_preserve_priority_and_boolean_casts() {
    for (site, charge, parent) in [
        (2, "false", ""),
        (6, "true", ""),
        (10, "true", "cac:InvoiceLine"),
        (66, "false", "cac:CreditNoteLine"),
    ] {
        let wrap = |content: &str| {
            if parent.is_empty() {
                content.into()
            } else {
                format!("<{parent}>{content}</{parent}>")
            }
        };
        let content = format!(
            "<cac:AllowanceCharge><cbc:ChargeIndicator>{charge}</cbc:ChargeIndicator></cac:AllowanceCharge>"
        );
        assert_eq!(check(site, &wrap(&content)).unwrap().len(), 1);
        assert!(
            check(
                site,
                &wrap(&content.replace(
                    "</cac:AllowanceCharge>",
                    "<cbc:Amount/></cac:AllowanceCharge>"
                ))
            )
            .unwrap()
            .is_empty()
        );
    }
    assert!(check(2, "<cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:ChargeIndicator>true</cbc:ChargeIndicator></cac:AllowanceCharge>").unwrap().is_empty());
    assert!(check(66, "<cac:InvoiceLine><cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator></cac:AllowanceCharge></cac:InvoiceLine>").unwrap().is_empty());
    assert_eq!(check(2, "<cac:AllowanceCharge><cbc:ChargeIndicator>False</cbc:ChargeIndicator></cac:AllowanceCharge>").unwrap_err().kind, FailureKind::InvalidBoolean);
}

#[test]
fn category_presence_checks_follow_tax_scheme_contexts() {
    let wrap = |category: &str| {
        format!(
            "<cac:InvoiceLine><cac:Item><cac:ClassifiedTaxCategory>{category}</cac:ClassifiedTaxCategory></cac:Item></cac:InvoiceLine>"
        )
    };
    assert_eq!(check(64, &wrap("<cbc:ID>S</cbc:ID>")).unwrap().len(), 1);
    assert!(
        check(
            64,
            &wrap("<cbc:ID/><cac:TaxScheme><cbc:ID> vat </cbc:ID></cac:TaxScheme>")
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        check(
            64,
            &wrap("<cbc:ID>S</cbc:ID><cac:TaxScheme><cbc:ID>GST</cbc:ID></cac:TaxScheme>")
        )
        .unwrap()
        .len(),
        1
    );
    assert_eq!(check(64, &wrap("<cbc:ID>S</cbc:ID><cac:TaxScheme><cbc:ID>VAT</cbc:ID><cbc:ID>VAT</cbc:ID></cac:TaxScheme>")).unwrap_err().kind, FailureKind::Cardinality);
    assert_eq!(check(64, &wrap("<cbc:ID>S</cbc:ID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>")).unwrap_err().kind, FailureKind::Cardinality);
    for value in ["123", "١٢٣", "११२", "1\u{1d7d8}3"] {
        assert_eq!(check(58, &format!("<cac:InvoiceLine><cac:Item><cbc:Name>{value}</cbc:Name></cac:Item></cac:InvoiceLine>")).unwrap().len(), 1);
    }
    assert!(check(58, "<cac:InvoiceLine><cac:Item><cbc:Name>123 apples</cbc:Name></cac:Item></cac:InvoiceLine>").unwrap().is_empty());
}

#[test]
fn suppressed_allowance_templates_still_cast_the_match_predicate() {
    assert_eq!(check(66, "<cac:InvoiceLine><cac:AllowanceCharge><cbc:ChargeIndicator>False</cbc:ChargeIndicator></cac:AllowanceCharge></cac:InvoiceLine>").unwrap_err().kind, FailureKind::InvalidBoolean);
}

#[test]
fn every_added_scale_context_checks_raw_fractional_characters() {
    for (site, prefix, field, suffix) in [
        (
            4,
            "<cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator>",
            "Amount",
            "</cac:AllowanceCharge>",
        ),
        (
            5,
            "<cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator>",
            "BaseAmount",
            "</cac:AllowanceCharge>",
        ),
        (
            8,
            "<cac:AllowanceCharge><cbc:ChargeIndicator>true</cbc:ChargeIndicator>",
            "BaseAmount",
            "</cac:AllowanceCharge>",
        ),
        (
            9,
            "<cac:AllowanceCharge><cbc:ChargeIndicator>true</cbc:ChargeIndicator>",
            "Amount",
            "</cac:AllowanceCharge>",
        ),
        (
            11,
            "<cac:InvoiceLine><cac:AllowanceCharge><cbc:ChargeIndicator>true</cbc:ChargeIndicator>",
            "Amount",
            "</cac:AllowanceCharge></cac:InvoiceLine>",
        ),
        (
            12,
            "<cac:InvoiceLine><cac:AllowanceCharge><cbc:ChargeIndicator>true</cbc:ChargeIndicator>",
            "BaseAmount",
            "</cac:AllowanceCharge></cac:InvoiceLine>",
        ),
        (
            65,
            "<cac:InvoiceLine>",
            "LineExtensionAmount",
            "</cac:InvoiceLine>",
        ),
        (
            79,
            "<cac:TaxTotal><cac:TaxSubtotal>",
            "TaxableAmount",
            "</cac:TaxSubtotal></cac:TaxTotal>",
        ),
        (
            80,
            "<cac:TaxTotal><cac:TaxSubtotal>",
            "TaxAmount",
            "</cac:TaxSubtotal></cac:TaxTotal>",
        ),
    ] {
        for (value, errors) in [("0.00", 0), ("0.000", 1), ("0.00 ", 1), ("", 0)] {
            assert_eq!(
                check(
                    site,
                    &format!("{prefix}<cbc:{field}>{value}</cbc:{field}>{suffix}")
                )
                .unwrap()
                .len(),
                errors,
                "{site}/{value}"
            );
        }
        assert_eq!(
            check(
                site,
                &format!(
                    "{prefix}<cbc:{field}>0</cbc:{field}><cbc:{field}>0</cbc:{field}>{suffix}"
                )
            )
            .unwrap_err()
            .kind,
            FailureKind::Cardinality
        );
    }
}

#[test]
fn nested_optional_strings_use_their_exact_source_paths() {
    for (site, prefix, suffix) in [
        (
            39,
            "<cac:AccountingSupplierParty><cac:Party><cac:PostalAddress><cbc:CountrySubentity>",
            "</cbc:CountrySubentity></cac:PostalAddress></cac:Party></cac:AccountingSupplierParty>",
        ),
        (
            41,
            "<cac:AccountingCustomerParty><cac:Party><cac:PostalAddress><cbc:CountrySubentity>",
            "</cbc:CountrySubentity></cac:PostalAddress></cac:Party></cac:AccountingCustomerParty>",
        ),
        (
            45,
            "<cac:InvoiceLine><cac:Item><cac:BuyersItemIdentification><cbc:ID>",
            "</cbc:ID></cac:BuyersItemIdentification></cac:Item></cac:InvoiceLine>",
        ),
        (
            46,
            "<cac:InvoiceLine><cac:Item><cac:SellersItemIdentification><cbc:ID>",
            "</cbc:ID></cac:SellersItemIdentification></cac:Item></cac:InvoiceLine>",
        ),
        (
            47,
            "<cac:InvoiceLine><cac:Item><cac:StandardItemIdentification><cbc:ID>",
            "</cbc:ID></cac:StandardItemIdentification></cac:Item></cac:InvoiceLine>",
        ),
    ] {
        for (len, expected) in [(127, 0), (128, 1)] {
            assert_eq!(
                check(site, &format!("{prefix}{}{suffix}", "ع".repeat(len)))
                    .unwrap()
                    .len(),
                expected,
                "{site}"
            );
        }
    }
    for (len, expected) in [(127, 0), (128, 1)] {
        assert_eq!(check(56, &format!("<cac:InvoiceLine><cbc:InvoicedQuantity unitCode='{}'>1</cbc:InvoicedQuantity></cac:InvoiceLine>", "u".repeat(len))).unwrap().len(), expected);
    }
    assert_eq!(check(56, "<cac:InvoiceLine><cbc:InvoicedQuantity unitCode='a'/><cbc:InvoicedQuantity unitCode='b'/></cac:InvoiceLine>").unwrap_err().kind, FailureKind::Cardinality);
}

#[test]
fn document_requirements_and_payment_guards_are_independent() {
    assert_eq!(check(35, "").unwrap().len(), 1);
    assert!(
        check(35, "<cbc:CreditNoteTypeCode>381</cbc:CreditNoteTypeCode>")
            .unwrap()
            .is_empty()
    );
    assert_eq!(check(37, "<cac:AccountingSupplierParty><cac:Party><cac:PartyLegalEntity><cbc:RegistrationName/></cac:PartyLegalEntity></cac:Party></cac:AccountingSupplierParty>").unwrap().len(), 1);
    assert!(check(37, "<cac:AccountingSupplierParty><cac:Party><cac:PartyLegalEntity><cbc:RegistrationName> </cbc:RegistrationName></cac:PartyLegalEntity></cac:Party></cac:AccountingSupplierParty>").unwrap().is_empty());
    assert_eq!(
        check(40, "<cac:AccountingSupplierParty/>").unwrap().len(),
        1
    );
    assert!(check(40, "<cac:AccountingSupplierParty><cac:Party><cac:PostalAddress/></cac:Party></cac:AccountingSupplierParty>").unwrap().is_empty());
    assert_eq!(check(42, "").unwrap().len(), 1);
    assert!(check(42, "<cac:CreditNoteLine/>").unwrap().is_empty());
    assert_eq!(check(49, "<cac:TaxTotal/>").unwrap().len(), 1);
    assert!(
        check(49, "<cac:TaxTotal><cac:TaxSubtotal/></cac:TaxTotal>")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        check(
            69,
            "<cac:AdditionalItemProperty><cbc:Name/></cac:AdditionalItemProperty>"
        )
        .unwrap()
        .len(),
        1
    );
    assert!(
        check(
            69,
            "<cac:AdditionalItemProperty><cbc:Name/><cbc:Value/></cac:AdditionalItemProperty>"
        )
        .unwrap()
        .is_empty()
    );
    assert!(check(70, "<cac:PaymentMeans/>").unwrap().is_empty());
    // Source matches @name on any element, anywhere in the attribute value.
    assert_eq!(
        check(
            70,
            "<cbc:Note name='prefix01١٢٣٤٥suffix'/><cac:PaymentMeans/>"
        )
        .unwrap()
        .len(),
        1
    );
    assert!(
        check(
            70,
            "<cbc:Note name='0100000'/><cac:PaymentMeans><cbc:PaymentMeansCode/></cac:PaymentMeans>"
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn vat_presence_rate_and_accounting_currency_keep_vacuous_cases() {
    for (site, indicator, vat_required) in [(3, "false", true), (7, "true", false)] {
        let wrap = |category: &str| {
            format!(
                "<cac:AllowanceCharge><cbc:ChargeIndicator>{indicator}</cbc:ChargeIndicator><cac:TaxCategory>{category}</cac:TaxCategory></cac:AllowanceCharge>"
            )
        };
        assert_eq!(check(site, &wrap("")).unwrap().len(), 1);
        assert_eq!(
            check(site, &wrap("<cbc:ID>S</cbc:ID>")).unwrap().len(),
            usize::from(vat_required)
        );
        assert!(
            check(
                site,
                &wrap("<cbc:ID>S</cbc:ID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>")
            )
            .unwrap()
            .is_empty()
        );
    }
    let wrap = |category: &str| {
        format!(
            "<cac:TaxTotal><cac:TaxSubtotal><cac:TaxCategory>{category}<cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal>"
        )
    };
    assert_eq!(check(76, &wrap("")).unwrap().len(), 1);
    assert!(check(76, &wrap("<cbc:ID/>")).unwrap().is_empty());
    assert_eq!(check(77, &wrap("<cbc:ID>S</cbc:ID>")).unwrap().len(), 1);
    assert!(check(77, &wrap("<cbc:ID> O </cbc:ID>")).unwrap().is_empty());
    assert!(
        check(77, &wrap("<cbc:ID>S</cbc:ID><cbc:Percent/>"))
            .unwrap()
            .is_empty()
    );
    for (body, expected) in [
        ("<cac:TaxTotal/>", 1),
        (
            "<cac:TaxTotal><cbc:TaxAmount>0</cbc:TaxAmount></cac:TaxTotal>",
            0,
        ),
        (
            "<cac:TaxTotal><cbc:TaxAmount currencyID='USD'>0</cbc:TaxAmount></cac:TaxTotal>",
            1,
        ),
        (
            "<cac:TaxTotal><cbc:TaxAmount currencyID='SAR'>0</cbc:TaxAmount></cac:TaxTotal>",
            0,
        ),
        ("", 0),
    ] {
        assert_eq!(
            check(
                43,
                &format!("<cbc:TaxCurrencyCode>SAR</cbc:TaxCurrencyCode>{body}")
            )
            .unwrap()
            .len(),
            expected
        );
        assert!(check(43, body).unwrap().is_empty());
    }
}
