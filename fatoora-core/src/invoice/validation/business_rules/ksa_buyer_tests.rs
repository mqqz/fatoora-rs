use super::{
    FailureKind, Limits,
    ksa_buyer::KsaBuyerCheck as K,
    xml::{CAC, CBC, UBL, XmlView},
};

fn view(body: &str) -> XmlView {
    XmlView::parse(
        &format!("<Invoice xmlns='{UBL}' xmlns:cac='{CAC}' xmlns:cbc='{CBC}'>{body}</Invoice>"),
        &Limits::default(),
    )
    .unwrap()
}
fn buyer(body: &str) -> String {
    format!(
        "<cac:AccountingCustomerParty><cac:Party>{body}</cac:Party></cac:AccountingCustomerParty>"
    )
}
fn typed(name: &str, value: &str, body: &str) -> String {
    format!("<cbc:InvoiceTypeCode name='{name}'>{value}</cbc:InvoiceTypeCode>{body}")
}
fn run(check: K, body: &str) -> Result<Vec<bool>, FailureKind> {
    let xml = view(body);
    check
        .contexts(&xml)
        .into_iter()
        .map(|n| check.passes(&xml, n))
        .collect()
}
#[test]
fn sa_address_rules_keep_country_context_and_standard_gate() {
    let address = "<cac:PostalAddress><cac:Country><cbc:IdentificationCode>SA</cbc:IdentificationCode></cac:Country></cac:PostalAddress>";
    for check in [K::SaAddress, K::DistrictRequired, K::Postcode] {
        assert_eq!(
            run(check, &typed("0100000", "388", &buyer(address))),
            Ok(vec![false])
        );
        assert_eq!(
            run(check, &typed("0200000", "388", &buyer(address))),
            Ok(vec![true])
        );
        assert_eq!(
            run(
                check,
                &typed("0100000", "388", &buyer(&address.replace("SA", " SA ")))
            ),
            Ok(vec![])
        );
    }
    assert_eq!(
        run(K::DistrictLength, &typed("0100000", "388", &buyer(address))),
        Ok(vec![true])
    );
    let district = format!(
        "<cac:AccountingSupplierParty><cac:Party><cac:PostalAddress><cbc:CitySubdivisionName>{}</cbc:CitySubdivisionName></cac:PostalAddress></cac:Party></cac:AccountingSupplierParty>",
        "x".repeat(128)
    );
    assert_eq!(
        run(
            K::SellerDistrict,
            &typed("0200000", "388", &(buyer(address) + &district))
        ),
        Ok(vec![false])
    );
    assert_eq!(run(K::SellerDistrict, &district), Ok(vec![]));
}
#[test]
fn summary_date_gate_matches_any_name_and_requires_presence_only() {
    let b = buyer(
        "<cac:PostalAddress><cac:Country><cbc:IdentificationCode>SA</cbc:IdentificationCode></cac:Country></cac:PostalAddress>",
    );
    assert_eq!(
        run(
            K::SummaryDates,
            &format!("<x name='prefix02١٢٣1٤suffix'/>{b}")
        ),
        Ok(vec![false])
    );
    assert_eq!(
        run(
            K::SummaryDates,
            &format!("<x name='0200010'/>{b}<cbc:ActualDeliveryDate/><cbc:LatestDeliveryDate/>")
        ),
        Ok(vec![true])
    );
    assert_eq!(
        run(K::SummaryDates, &format!("<x name='0200000'/>{b}")),
        Ok(vec![true])
    );
}
#[test]
fn line_presence_uses_general_comparison_and_vacuous_every() {
    for (check, field) in [
        (K::LineTax, "TaxAmount"),
        (K::LineInclusive, "RoundingAmount"),
    ] {
        assert_eq!(run(check, &typed("0100000", "388", "")), Ok(vec![true]));
        assert_eq!(
            run(check, &typed("0100000", "388", "<cac:InvoiceLine/>")),
            Ok(vec![false])
        );
        let line = format!(
            "<cac:InvoiceLine><cac:TaxTotal><cbc:{field}/><cbc:{field}> </cbc:{field}></cac:TaxTotal></cac:InvoiceLine>"
        );
        assert_eq!(run(check, &typed("0100000", "388", &line)), Ok(vec![true]));
        assert_eq!(
            run(check, &typed("0200000", "388", "<cac:InvoiceLine/>")),
            Ok(vec![true])
        );
    }
}
#[test]
fn buyer_lengths_use_raw_text_global_singletons_and_optional_gates() {
    for (check, name, field, max, required) in [
        (K::StreetRequired, "0100000", "StreetName", 1000, true),
        (K::CityRequired, "0100000", "CityName", usize::MAX, true),
        (K::SimpleStreetLength, "0200000", "StreetName", 1000, false),
        (K::CityLength, "0200000", "CityName", 127, false),
    ] {
        assert_eq!(run(check, &typed(name, "388", "")), Ok(vec![!required]));
        for (value, pass) in [
            (" ".into(), true),
            ("".into(), !required),
            (
                "x".repeat(if max == usize::MAX { 1001 } else { max + 1 }),
                max == usize::MAX,
            ),
        ] {
            assert_eq!(
                run(
                    check,
                    &typed(
                        name,
                        "388",
                        &buyer(&format!(
                            "<cac:PostalAddress><cbc:{field}>{value}</cbc:{field}></cac:PostalAddress>"
                        ))
                    )
                ),
                Ok(vec![pass])
            );
        }
        let duplicate = buyer(&format!(
            "<cac:PostalAddress><cbc:{field}>a</cbc:{field}><cbc:{field}>b</cbc:{field}></cac:PostalAddress>"
        ));
        assert_eq!(
            run(check, &typed(name, "388", &duplicate)),
            Err(FailureKind::Cardinality)
        );
    }
    for (check, name, min) in [
        (K::StandardNameLength, "0100000", 1),
        (K::SimpleNameLength, "0200000", 0),
    ] {
        for (value, pass) in [
            ("".into(), min == 0),
            ("x".repeat(1000), true),
            ("x".repeat(1001), false),
        ] {
            assert_eq!(
                run(
                    check,
                    &typed(
                        name,
                        "388",
                        &buyer(&format!(
                            "<cac:PartyLegalEntity><cbc:RegistrationName>{value}</cbc:RegistrationName></cac:PartyLegalEntity>"
                        ))
                    )
                ),
                Ok(vec![pass])
            );
        }
        assert_eq!(run(check, &typed(name, "388", "")), Ok(vec![true]));
    }
}
#[test]
fn payment_lengths_and_ksa_payment_list_keep_independent_scope() {
    for (check, field, max, min) in [
        (K::PaymentNoteLength, "PaymentNote", 1000, 1),
        (K::AccountLength, "ID", 127, 0),
    ] {
        for (value, pass) in [
            ("".into(), min == 0),
            ("x".repeat(max), true),
            ("x".repeat(max + 1), false),
        ] {
            let p = format!(
                "<cac:PaymentMeans><cac:PayeeFinancialAccount><cbc:{field}>{value}</cbc:{field}></cac:PayeeFinancialAccount></cac:PaymentMeans>"
            );
            assert_eq!(run(check, &typed("0200000", "388", &p)), Ok(vec![pass]));
        }
        assert_eq!(run(check, &typed("0100000", "388", "")), Ok(vec![true]));
    }
    for (code, pass) in [
        ("68", true),
        ("69", false),
        ("70", true),
        (" ZZZ ", true),
        ("", false),
        ("1 2", false),
    ] {
        let p = format!(
            "<cac:PaymentMeans><cbc:PaymentMeansCode>{code}</cbc:PaymentMeansCode></cac:PaymentMeans>"
        );
        assert_eq!(
            run(K::PaymentCode, &typed("0100000", "388", &p)),
            Ok(vec![pass])
        );
        assert_eq!(
            run(
                K::PaymentCode,
                &typed("0100000", "388", &typed("0200000", "388", &p))
            ),
            Ok(vec![pass, pass])
        );
    }
}
#[test]
fn address_and_supply_requirements_preserve_reported_test_differences() {
    let a = buyer(
        "<cac:PostalAddress><cbc:StreetName> </cbc:StreetName><cbc:CityName> </cbc:CityName><cac:Country><cbc:IdentificationCode>SA</cbc:IdentificationCode></cac:Country></cac:PostalAddress>",
    );
    assert_eq!(
        run(K::BuyerAddress, &typed("0100000", "388", &a)),
        Ok(vec![true])
    );
    assert_eq!(
        run(K::BuyerAddress, &typed("0100000", "388", "")),
        Ok(vec![false])
    );
    assert_eq!(
        run(K::BuyerAddress, &typed("0200000", "388", "")),
        Ok(vec![true])
    );
    assert_eq!(
        run(K::SupplyDate, &typed("0100000", "388", "")),
        Ok(vec![false])
    );
    assert_eq!(run(K::SupplyDate, &typed("0100000", "381", "")), Ok(vec![]));
    assert_eq!(
        run(
            K::SupplyDate,
            &typed(
                "0100000",
                "388",
                "<cac:Delivery><cbc:ActualDeliveryDate> </cbc:ActualDeliveryDate></cac:Delivery>"
            )
        ),
        Ok(vec![false])
    );
}
#[test]
fn credit_and_debit_note_branches_preserve_distinct_sites_and_locations() {
    for t in ["381", "383"] {
        assert_eq!(
            run(K::MissingPayment, &typed("0100000", t, "")),
            Ok(vec![false])
        );
        assert_eq!(
            run(K::NoteReason, &typed("0100000", t, "<cac:PaymentMeans/>")),
            Ok(vec![false])
        );
        assert_eq!(
            run(
                K::NoteReason,
                &typed(
                    "0100000",
                    t,
                    "<cac:PaymentMeans><cbc:InstructionNote/></cac:PaymentMeans>"
                )
            ),
            Ok(vec![true])
        );
        assert_eq!(
            run(
                K::NoteReasonLength,
                &typed(
                    "0100000",
                    t,
                    "<cac:PaymentMeans><cbc:InstructionNote/></cac:PaymentMeans>"
                )
            ),
            Ok(vec![false])
        );
        assert_eq!(
            run(K::MissingReference, &typed("0100000", t, "")),
            Ok(vec![false])
        );
        assert_eq!(
            run(
                K::NoteReference,
                &typed("0100000", t, "<cac:BillingReference/>")
            ),
            Ok(vec![false])
        );
        let r = "<cac:BillingReference><cac:InvoiceDocumentReference><cbc:ID/></cac:InvoiceDocumentReference></cac:BillingReference>";
        assert_eq!(
            run(K::NoteReferenceLength, &typed("0100000", t, r)),
            Ok(vec![false])
        );
        assert_eq!(
            run(
                K::NoteReference,
                &typed("0100000", t, &r.replace("<cbc:ID/>", "<cbc:ID> </cbc:ID>"))
            ),
            Ok(vec![true])
        );
    }
    for c in [
        K::MissingPayment,
        K::NoteReason,
        K::NoteReasonLength,
        K::MissingReference,
        K::NoteReference,
        K::NoteReferenceLength,
    ] {
        assert_eq!(run(c, &typed("0100000", "388", "")), Ok(vec![]));
    }
}
#[test]
fn simplified_and_export_predicates_keep_global_and_local_gates() {
    assert_eq!(
        run(K::SimpleBuyer, &typed("0200000", "388", "")),
        Ok(vec![true])
    ); // every empty sequence is true
    let edu = "<cac:TaxTotal><cac:TaxSubtotal><cac:TaxCategory><cbc:TaxExemptionReasonCode>VATEX-SA-EDU</cbc:TaxExemptionReasonCode></cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal>";
    assert_eq!(
        run(K::SimpleBuyer, &typed("0200000", "388", edu)),
        Ok(vec![false])
    );
    let name = buyer(
        "<cac:PartyLegalEntity><cbc:RegistrationName> </cbc:RegistrationName></cac:PartyLegalEntity>",
    );
    assert_eq!(
        run(K::SimpleBuyer, &typed("0200000", "388", &name)),
        Ok(vec![true])
    );
    let category = "<cac:TaxTotal><cac:TaxSubtotal><cac:TaxCategory><cbc:TaxExemptionReasonCode>VATEX-SA-32</cbc:TaxExemptionReasonCode></cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal>";
    assert_eq!(
        run(K::SimpleBuyer, &typed("0200000", "388", category)),
        Ok(vec![true])
    );
    for (name, pass) in [
        ("0200000", true),
        ("0211110", true),
        ("0200001", false),
        ("0202000", false),
    ] {
        assert_eq!(run(K::SimpleFlags, &typed(name, "388", "")), Ok(vec![pass]));
    }
    assert_eq!(
        run(
            K::Stamp,
            &typed("0200000", "388", "<cac:Signature> </cac:Signature>")
        ),
        Ok(vec![true])
    );
    assert_eq!(
        run(K::Stamp, &typed("0200000", "388", "<cac:Signature/>")),
        Ok(vec![false])
    );
    assert_eq!(
        run(K::SummaryBuyer, &typed("0200010", "388", &name)),
        Ok(vec![false])
    );
    assert_eq!(
        run(
            K::SummaryBuyer,
            &typed(
                "0200010",
                "388",
                &name
                    .replace("<cac:PartyLegalEntity>", "<other><cac:PartyLegalEntity>")
                    .replace("</cac:PartyLegalEntity>", "</cac:PartyLegalEntity></other>")
                    .replace("> </cbc:RegistrationName>", ">Buyer</cbc:RegistrationName>")
            )
        ),
        Ok(vec![true])
    );
    assert_eq!(
        run(K::ExportSelfBilling, &typed("0100101", "388", "")),
        Ok(vec![false])
    );
    assert_eq!(
        run(K::ExportSelfBilling, &typed("0100100", "388", "")),
        Ok(vec![true])
    );
    let v = buyer("<cac:PartyTaxScheme><cbc:CompanyID> </cbc:CompanyID></cac:PartyTaxScheme>");
    assert_eq!(
        run(K::EmptyBuyerVat, &typed("0100000", "388", &v)),
        Ok(vec![false])
    );
    assert_eq!(
        run(K::EmptyBuyerVat, &typed("0200000", "388", &v)),
        Ok(vec![true])
    );
}

#[test]
fn district_length_counts_unicode_characters_at_the_source_boundary() {
    for (length, valid) in [(0, true), (127, true), (128, false)] {
        let address = buyer(&format!(
            "<cac:PostalAddress><cbc:CitySubdivisionName>{}</cbc:CitySubdivisionName><cac:Country><cbc:IdentificationCode>SA</cbc:IdentificationCode></cac:Country></cac:PostalAddress>",
            "ع".repeat(length)
        ));
        assert_eq!(
            run(K::DistrictLength, &typed("0100000", "388", &address)),
            Ok(vec![valid]),
            "district length {length}"
        );
    }
}

#[test]
fn sa_postcode_requires_five_ascii_digits_without_trimming() {
    for (value, valid) in [
        ("12345", true),
        ("01234", true),
        ("1234", false),
        ("123456", false),
        ("1234x", false),
        ("١٢٣٤٥", false),
        ("１２３４５", false),
        (" 12345", false),
        ("12345 ", false),
        ("", false),
    ] {
        let address = buyer(&format!(
            "<cac:PostalAddress><cbc:PostalZone>{value}</cbc:PostalZone><cac:Country><cbc:IdentificationCode>SA</cbc:IdentificationCode></cac:Country></cac:PostalAddress>"
        ));
        assert_eq!(
            run(K::Postcode, &typed("0100000", "388", &address)),
            Ok(vec![valid]),
            "postcode {value:?}"
        );
    }
}

#[test]
fn note_reason_lengths_apply_to_each_note_with_unicode_boundaries() {
    for invoice_type in ["381", "383"] {
        for (length, valid) in [(1, true), (1000, true), (1001, false)] {
            let payment = format!(
                "<cac:PaymentMeans><cbc:InstructionNote>{}</cbc:InstructionNote></cac:PaymentMeans>",
                "💰".repeat(length)
            );
            assert_eq!(
                run(
                    K::NoteReasonLength,
                    &typed("0100000", invoice_type, &payment)
                ),
                Ok(vec![valid]),
                "type {invoice_type}, reason length {length}"
            );
        }
        let payment = format!(
            "<cac:PaymentMeans><cbc:InstructionNote>valid</cbc:InstructionNote><cbc:InstructionNote>{}</cbc:InstructionNote></cac:PaymentMeans>",
            "x".repeat(1001)
        );
        assert_eq!(
            run(
                K::NoteReasonLength,
                &typed("0100000", invoice_type, &payment)
            ),
            Ok(vec![true, false])
        );
    }
}

#[test]
fn note_reference_length_keeps_per_reference_scalar_cardinality() {
    for invoice_type in ["381", "383"] {
        for (length, valid) in [(1, true), (5000, true), (5001, false)] {
            let reference = format!(
                "<cac:BillingReference><cac:InvoiceDocumentReference><cbc:ID>{}</cbc:ID></cac:InvoiceDocumentReference></cac:BillingReference>",
                "ع".repeat(length)
            );
            assert_eq!(
                run(
                    K::NoteReferenceLength,
                    &typed("0100000", invoice_type, &reference)
                ),
                Ok(vec![valid]),
                "type {invoice_type}, reference length {length}"
            );
        }
        for reference in [
            "<cac:BillingReference><cac:InvoiceDocumentReference><cbc:ID>a</cbc:ID><cbc:ID>b</cbc:ID></cac:InvoiceDocumentReference></cac:BillingReference>",
            "<cac:BillingReference><cac:InvoiceDocumentReference><cbc:ID>a</cbc:ID></cac:InvoiceDocumentReference><cac:InvoiceDocumentReference><cbc:ID>b</cbc:ID></cac:InvoiceDocumentReference></cac:BillingReference>",
        ] {
            assert_eq!(
                run(
                    K::NoteReferenceLength,
                    &typed("0100000", invoice_type, reference)
                ),
                Err(FailureKind::Cardinality)
            );
        }
        let separate = format!(
            "<cac:BillingReference><cac:InvoiceDocumentReference><cbc:ID>a</cbc:ID></cac:InvoiceDocumentReference></cac:BillingReference><cac:BillingReference><cac:InvoiceDocumentReference><cbc:ID>{}</cbc:ID></cac:InvoiceDocumentReference></cac:BillingReference>",
            "x".repeat(5001)
        );
        assert_eq!(
            run(
                K::NoteReferenceLength,
                &typed("0100000", invoice_type, &separate)
            ),
            Ok(vec![true, false])
        );
    }
}

#[test]
fn supply_date_uses_a_global_normalized_singleton() {
    for body in [
        "<cac:Delivery><cbc:ActualDeliveryDate>2026-09-23</cbc:ActualDeliveryDate></cac:Delivery>",
        "<cac:Delivery><cbc:ActualDeliveryDate> 2026-09-23 </cbc:ActualDeliveryDate></cac:Delivery>",
        "<cac:InvoiceLine><cac:Delivery><cbc:ActualDeliveryDate>2026-09-23</cbc:ActualDeliveryDate></cac:Delivery></cac:InvoiceLine>",
    ] {
        assert_eq!(
            run(K::SupplyDate, &typed("0100000", "388", body)),
            Ok(vec![true])
        );
    }
    for body in [
        "<cac:Delivery><cbc:ActualDeliveryDate>2026-09-23</cbc:ActualDeliveryDate><cbc:ActualDeliveryDate>2026-09-23</cbc:ActualDeliveryDate></cac:Delivery>",
        "<cac:Delivery><cbc:ActualDeliveryDate>2026-09-23</cbc:ActualDeliveryDate></cac:Delivery><cac:InvoiceLine><cac:Delivery><cbc:ActualDeliveryDate>2026-09-23</cbc:ActualDeliveryDate></cac:Delivery></cac:InvoiceLine>",
    ] {
        assert_eq!(
            run(K::SupplyDate, &typed("0100000", "388", body)),
            Err(FailureKind::Cardinality)
        );
    }
}
