use super::{
    Limits,
    code_lists::CodeListCheck as C,
    xml::{CAC, CBC, CREDIT_NOTE, UBL, XmlView},
};

fn document(namespace: &str, name: &str, body: &str) -> XmlView {
    XmlView::parse(
        &format!(
            "<{name} xmlns='{namespace}' xmlns:cac='{CAC}' xmlns:cbc='{CBC}' xmlns:other='urn:other'>{body}</{name}>"
        ),
        &Limits::default(),
    )
    .unwrap()
}

fn check(check: C, body: &str) -> Vec<bool> {
    let xml = document(UBL, "Invoice", body);
    check
        .contexts(&xml)
        .into_iter()
        .map(|node| check.passes(&xml, node).unwrap())
        .collect()
}

fn code(check_kind: C, value: &str) -> bool {
    let body = match check_kind {
        C::DocumentType => format!("<cbc:InvoiceTypeCode>{value}</cbc:InvoiceTypeCode>"),
        C::AmountCurrency => format!("<cbc:Amount currencyID='{value}'>1</cbc:Amount>"),
        C::DocumentCurrency => {
            format!("<cbc:DocumentCurrencyCode>{value}</cbc:DocumentCurrencyCode>")
        }
        C::TaxCurrency => format!("<cbc:TaxCurrencyCode>{value}</cbc:TaxCurrencyCode>"),
        C::Country => format!(
            "<cac:Country><cbc:IdentificationCode>{value}</cbc:IdentificationCode></cac:Country>"
        ),
        C::PaymentMeans => format!(
            "<cac:PaymentMeans><cbc:PaymentMeansCode>{value}</cbc:PaymentMeansCode></cac:PaymentMeans>"
        ),
        C::TaxCategory => format!(
            "<cac:AllowanceCharge><cac:TaxCategory><cbc:ID>{value}</cbc:ID></cac:TaxCategory></cac:AllowanceCharge>"
        ),
    };
    let results = check(check_kind, &body);
    assert_eq!(results.len(), 1);
    results[0]
}

#[test]
fn pinned_lists_keep_historical_codes_and_extensions() {
    for check in [C::AmountCurrency, C::DocumentCurrency, C::TaxCurrency] {
        for value in ["AED", "SAR", "USD", "ZWL", "MRO", "VEF", "STD", "XXX"] {
            assert!(code(check, value), "{check:?}: {value}");
        }
        for value in ["MRU", "VES", "STN", "ZZZ", "sar", "US", "USDD"] {
            assert!(!code(check, value), "{check:?}: {value}");
        }
    }
    for value in ["1A", "AD", "SA", "XI", "ZW"] {
        assert!(code(C::Country, value), "{value}");
    }
    for value in ["SAU", "UK", "XK", "ZZ", "sa"] {
        assert!(!code(C::Country, value), "{value}");
    }
    for value in ["1", "70", "74", "78", "91", "97", "ZZZ"] {
        assert!(code(C::PaymentMeans, value), "{value}");
    }
    for value in ["0", "71", "73", "79", "90", "98", "01", "ZZ"] {
        assert!(!code(C::PaymentMeans, value), "{value}");
    }
    for value in ["AE", "L", "M", "E", "S", "Z", "G", "O", "K", "B"] {
        assert!(code(C::TaxCategory, value), "{value}");
    }
    for value in ["A", "SE", "s", "1"] {
        assert!(!code(C::TaxCategory, value), "{value}");
    }
}

#[test]
fn document_type_uses_different_invoice_and_credit_note_lists() {
    assert_eq!(
        check(
            C::DocumentType,
            "<cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode><cbc:CreditNoteTypeCode>380</cbc:CreditNoteTypeCode><cbc:InvoiceTypeCode>81</cbc:InvoiceTypeCode><cbc:CreditNoteTypeCode>81</cbc:CreditNoteTypeCode>"
        ),
        [true, false, false, true]
    );
    for value in ["80", "935", "381", "383", "388"] {
        assert!(code(C::DocumentType, value));
    }
    for value in ["8", "0380", "3800", "81", ""] {
        assert!(!code(C::DocumentType, value));
    }
    for value in [
        "81", "83", "261", "262", "296", "308", "396", "420", "458", "532",
    ] {
        assert_eq!(
            check(
                C::DocumentType,
                &format!("<cbc:CreditNoteTypeCode>{value}</cbc:CreditNoteTypeCode>")
            ),
            [true]
        );
    }
}

#[test]
fn membership_uses_source_xml_whitespace_and_delimited_substrings() {
    for (check, valid) in [
        (C::DocumentType, "380"),
        (C::DocumentCurrency, "SAR"),
        (C::TaxCurrency, "SAR"),
        (C::Country, "SA"),
        (C::PaymentMeans, "10"),
        (C::TaxCategory, "S"),
    ] {
        assert!(code(check, &format!(" \t{valid}\r\n ")));
        for invalid in [
            String::new(),
            " \t\n".into(),
            format!("\u{a0}{valid}\u{a0}"),
            format!("{valid} {valid}"),
            format!("{valid}\t{valid}"),
            format!("{valid}0"),
        ] {
            assert!(!code(check, &invalid), "{check:?}: {invalid:?}");
        }
    }
    // These are contiguous substrings of the literal list, but the source
    // separately prohibits a normalized internal space.
    assert!(!code(C::DocumentType, "80 82"));
    assert!(!code(C::DocumentCurrency, "AED AFN"));
    assert!(!code(C::Country, "SA SB"));
    assert!(!code(C::PaymentMeans, "1 2"));
    assert!(!code(C::TaxCategory, "AE L"));
}

#[test]
fn amount_currency_uses_raw_attribute_presence_and_length_guard() {
    assert_eq!(
        check(
            C::AmountCurrency,
            "<cbc:Amount/><cbc:Amount currencyID=''/><cbc:Amount currencyID=' '/><cbc:Amount currencyID='&#9;SAR&#10;'/><cbc:Amount currencyID='&#160;SAR'/><cbc:Amount other:currencyID='USD'/><cbc:Amount currencyID='SAR' other:currencyID='bad'/><cbc:Amount currencyID='bad' other:currencyID='SAR'/>"
        ),
        [true, true, false, true, false, true, true, false]
    );
    for value in ["SAR USD", "AR", "SARX", "sar"] {
        assert!(!code(C::AmountCurrency, value));
    }
}

#[test]
fn contexts_match_exact_names_and_direct_parent_steps() {
    const AMOUNTS: &[&str] = &[
        "Amount",
        "BaseAmount",
        "PriceAmount",
        "TaxAmount",
        "TaxableAmount",
        "LineExtensionAmount",
        "TaxExclusiveAmount",
        "TaxInclusiveAmount",
        "AllowanceTotalAmount",
        "ChargeTotalAmount",
        "PrepaidAmount",
        "PayableRoundingAmount",
        "PayableAmount",
    ];
    let body: String = AMOUNTS
        .iter()
        .map(|name| format!("<cbc:{name} currencyID='SAR'/>"))
        .collect();
    assert_eq!(check(C::AmountCurrency, &body), vec![true; AMOUNTS.len()]);
    assert!(check(C::AmountCurrency, "<cbc:RoundingAmount currencyID='bad'/><other:Amount currencyID='bad'/><cac:Amount currencyID='bad'/>").is_empty());
    assert_eq!(
        check(
            C::Country,
            "<cbc:IdentificationCode>bad</cbc:IdentificationCode><other:Country><cbc:IdentificationCode>bad</cbc:IdentificationCode></other:Country><cac:Country><other:IdentificationCode>bad</other:IdentificationCode><cac:Wrapper><cbc:IdentificationCode>bad</cbc:IdentificationCode></cac:Wrapper><cbc:IdentificationCode>SA</cbc:IdentificationCode><cbc:IdentificationCode>bad</cbc:IdentificationCode></cac:Country>"
        ),
        [true, false]
    );
    assert_eq!(
        check(
            C::PaymentMeans,
            "<cbc:PaymentMeansCode>bad</cbc:PaymentMeansCode><other:PaymentMeans><cbc:PaymentMeansCode>bad</cbc:PaymentMeansCode></other:PaymentMeans><cac:PaymentMeans><other:PaymentMeansCode>bad</other:PaymentMeansCode><cac:Wrapper><cbc:PaymentMeansCode>bad</cbc:PaymentMeansCode></cac:Wrapper><cbc:PaymentMeansCode>10</cbc:PaymentMeansCode></cac:PaymentMeans>"
        ),
        [true]
    );
    for (check_kind, name) in [
        (C::DocumentCurrency, "DocumentCurrencyCode"),
        (C::TaxCurrency, "TaxCurrencyCode"),
    ] {
        assert_eq!(
            check(
                check_kind,
                &format!(
                    "<other:{name}>bad</other:{name}><cac:Wrapper><cbc:{name}>SAR</cbc:{name}><cbc:{name}>bad</cbc:{name}></cac:Wrapper>"
                )
            ),
            [true, false]
        );
    }
}

#[test]
fn tax_category_contexts_cover_only_four_root_invoice_paths() {
    let body = "<cac:AllowanceCharge><cac:TaxCategory><cbc:ID>S</cbc:ID></cac:TaxCategory></cac:AllowanceCharge><cac:TaxTotal><cac:TaxSubtotal><cac:TaxCategory><cbc:ID>Z</cbc:ID></cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal><cac:InvoiceLine><cac:Item><cac:ClassifiedTaxCategory><cbc:ID>E</cbc:ID></cac:ClassifiedTaxCategory></cac:Item><cac:TaxTotal><cac:TaxSubtotal><cac:TaxCategory><cbc:ID>bad</cbc:ID></cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal><cac:AllowanceCharge><cac:TaxCategory><cbc:ID>bad</cbc:ID></cac:TaxCategory></cac:AllowanceCharge></cac:InvoiceLine><cac:TaxCategory><cbc:ID>bad</cbc:ID></cac:TaxCategory><cac:Item><cac:ClassifiedTaxCategory><cbc:ID>bad</cbc:ID></cac:ClassifiedTaxCategory></cac:Item>";
    assert_eq!(check(C::TaxCategory, body), [true, true, true, false]);
    for (namespace, name) in [
        (CREDIT_NOTE, "CreditNote"),
        ("urn:other", "Invoice"),
        (UBL, "Other"),
    ] {
        assert!(
            C::TaxCategory
                .contexts(&document(namespace, name, body))
                .is_empty()
        );
    }
    let nested = document(
        "urn:other",
        "Wrapper",
        &format!("<Invoice xmlns='{UBL}'>{body}</Invoice>"),
    );
    assert!(C::TaxCategory.contexts(&nested).is_empty());
}

#[test]
fn source_operands_use_element_string_values_and_preserve_repeated_nodes() {
    assert_eq!(
        check(
            C::DocumentCurrency,
            "<cbc:DocumentCurrencyCode>S<other:part>A</other:part>R</cbc:DocumentCurrencyCode><cbc:DocumentCurrencyCode>SA<!-- split -->R</cbc:DocumentCurrencyCode><cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode><cbc:DocumentCurrencyCode>bad</cbc:DocumentCurrencyCode>"
        ),
        [true, true, true, false]
    );
    assert_eq!(
        check(
            C::DocumentType,
            "<other:InvoiceTypeCode>bad</other:InvoiceTypeCode><cbc:InvoiceTypeCode>3<![CDATA[8]]>0</cbc:InvoiceTypeCode>"
        ),
        [true]
    );
}

#[test]
fn every_pinned_source_code_is_accepted_by_its_native_check() {
    let catalog: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/business-rules/catalog.json"
    ))
    .unwrap();
    for (index, check_kind) in [
        (98, C::AmountCurrency),
        (99, C::DocumentCurrency),
        (100, C::TaxCurrency),
        (101, C::Country),
        (102, C::PaymentMeans),
        (103, C::TaxCategory),
    ] {
        let assertion = &catalog["sources"][0]["assertions"][index];
        let predicate = assertion["control_flow"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["attributes"]["test"]
            .as_str()
            .unwrap();
        let codes = predicate
            .split('\'')
            .skip(1)
            .step_by(2)
            .filter(|part| part.starts_with(' ') && part.ends_with(' '))
            .max_by_key(|part| part.len())
            .unwrap();
        assert!(codes.starts_with(' ') && codes.ends_with(' '));
        for value in codes.split_whitespace() {
            assert!(code(check_kind, value), "{check_kind:?}: {value}");
        }
    }
    let predicate = catalog["sources"][0]["assertions"][97]["control_flow"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["attributes"]["test"]
        .as_str()
        .unwrap();
    let lists: Vec<_> = predicate
        .split('\'')
        .skip(1)
        .step_by(2)
        .filter(|part| part.len() > 2 && part.starts_with(' ') && part.ends_with(' '))
        .collect();
    assert_eq!(lists.len(), 2);
    for (name, list) in ["InvoiceTypeCode", "CreditNoteTypeCode"]
        .into_iter()
        .zip(lists)
    {
        for value in list.split_whitespace() {
            assert_eq!(
                check(
                    C::DocumentType,
                    &format!("<cbc:{name}>{value}</cbc:{name}>")
                ),
                [true],
                "{name}: {value}"
            );
        }
    }
}
