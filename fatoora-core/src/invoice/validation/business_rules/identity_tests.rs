use super::{identity::IdentityCheck as I, *};

fn check(check: I, body: &str) -> Result<Vec<bool>, FailureKind> {
    let input = format!(
        "<Invoice xmlns='{}' xmlns:cac='{}' xmlns:cbc='{}'>{body}</Invoice>",
        xml::UBL,
        xml::CAC,
        xml::CBC,
    );
    let xml = xml::XmlView::parse(&input, &Limits::default())?;
    check
        .contexts(&xml)
        .into_iter()
        .map(|id| check.passes(&xml, id))
        .collect()
}

fn party(role: &str, content: &str) -> String {
    format!(
        "<cac:Accounting{role}Party><cac:Party>{content}</cac:Party></cac:Accounting{role}Party>"
    )
}

fn identifier(role: &str, scheme: &str, value: &str) -> String {
    party(
        role,
        &format!(
            "<cac:PartyIdentification><cbc:ID schemeID='{scheme}'>{value}</cbc:ID></cac:PartyIdentification>"
        ),
    )
}

#[test]
fn identifier_lengths_prefixes_and_untrimmed_digit_checks() {
    for (rule, role, scheme, valid, invalid) in [
        (I::Crn, "Supplier", "CRN", "1234567890", "123456789"),
        (I::UnifiedId, "Supplier", "700", "7123456789", "6123456789"),
        (I::BuyerTin, "Customer", "TIN", "3123456789", "4123456789"),
        (
            I::BuyerNationalId,
            "Customer",
            "NAT",
            "1123456789",
            "2123456789",
        ),
        (
            I::BuyerResidenceId,
            "Customer",
            "IQA",
            "2123456789",
            "1123456789",
        ),
    ] {
        assert_eq!(
            check(rule, &identifier(role, scheme, valid)).unwrap(),
            [true]
        );
        for value in [
            invalid.to_string(),
            format!(" {valid} "),
            "١٢٣٤٥٦٧٨٩٠".into(),
        ] {
            assert_eq!(
                check(rule, &identifier(role, scheme, &value)).unwrap(),
                [false]
            );
        }
        assert_eq!(
            check(rule, &identifier(role, "OTH", "anything")).unwrap(),
            [true]
        );
    }
}

#[test]
fn identifier_spacing_and_patterns_preserve_scheme_and_role_gates() {
    for role in ["Supplier", "Customer"] {
        assert_eq!(
            check(
                I::SchemeWhitespace,
                &identifier(role, " CRN ", "1234567890")
            )
            .unwrap(),
            [false]
        );
        assert_eq!(
            check(I::SchemeWhitespace, &identifier(role, "crn", "1234567890")).unwrap(),
            [true]
        );
        assert_eq!(
            check(
                I::SchemeWhitespace,
                &identifier(role, " BAD ", "1234567890")
            )
            .unwrap(),
            [true]
        );
        for value in ["0000000012", "991234567899", "98765432", " 11111111 "] {
            assert_eq!(
                check(I::PredictableId, &identifier(role, " crn ", value)).unwrap(),
                [false]
            );
        }
        for value in [
            "1234567",
            "A12345678",
            "1234 5678",
            "1324354657",
            "١٢٣٤٥٦٧٨",
        ] {
            assert_eq!(
                check(I::PredictableId, &identifier(role, "CRN", value)).unwrap(),
                [true]
            );
        }
    }
    assert_eq!(
        check(
            I::PredictableId,
            &identifier("Supplier", "NAT", "1111111111")
        )
        .unwrap(),
        [true]
    );
    assert_eq!(
        check(
            I::PredictableId,
            &identifier("Customer", "NAT", "1111111111")
        )
        .unwrap(),
        [false]
    );
}

#[test]
fn buyer_scheme_uses_source_substring_test_and_xml_whitespace() {
    for (scheme, expected) in [
        ("TIN", true),
        (" TIN ", true),
        ("TIN NAT", true),
        ("TIN\u{a0}", false),
        ("TI", false),
        ("tin", false),
        ("BAD", false),
    ] {
        assert_eq!(
            check(I::BuyerScheme, &identifier("Customer", scheme, "1")).unwrap(),
            [expected],
            "{scheme}"
        );
    }
}

#[test]
fn scalar_identity_paths_reject_repetition_instead_of_picking_first() {
    let body = party(
        "Supplier",
        "<cac:PartyIdentification><cbc:ID schemeID='CRN'>1234567890</cbc:ID><cbc:ID schemeID='CRN'>1234567890</cbc:ID></cac:PartyIdentification>",
    );
    assert_eq!(check(I::Crn, &body).unwrap_err(), FailureKind::Cardinality);
    assert_eq!(
        check(I::SchemeWhitespace, &body).unwrap_err(),
        FailureKind::Cardinality
    );
    // The bad-pattern test is existential, not a singleton conversion.
    assert_eq!(check(I::PredictableId, &body).unwrap(), [false]);
}

#[test]
fn seller_address_presence_and_lexical_bounds_are_separate() {
    let fields = "<cbc:StreetName/><cbc:BuildingNumber/><cbc:CityName/><cbc:PostalZone/><cbc:CitySubdivisionName/><cac:Country><cbc:IdentificationCode/></cac:Country>";
    let address = |content: &str| {
        party(
            "Supplier",
            &format!("<cac:PostalAddress>{content}</cac:PostalAddress>"),
        )
    };
    assert_eq!(check(I::SellerAddress, &address(fields)).unwrap(), [true]);
    assert_eq!(
        check(
            I::SellerAddress,
            &address(&fields.replace("<cbc:CityName/>", ""))
        )
        .unwrap(),
        [false]
    );
    for (rule, field, min, max) in [
        (I::SellerStreet, "StreetName", 1, 1000),
        (I::SellerCity, "CityName", 1, 127),
        (I::SellerAdditionalStreet, "AdditionalStreetName", 0, 127),
    ] {
        assert_eq!(check(rule, &address("")).unwrap(), [true]);
        for len in [0, min, max, max + 1] {
            let body = address(&format!("<cbc:{field}>{}</cbc:{field}>", "💰".repeat(len)));
            assert_eq!(check(rule, &body).unwrap(), [len >= min && len <= max]);
        }
    }
    for (value, expected) in [
        ("12345", true),
        ("01234", true),
        ("1234", false),
        ("12345 ", false),
        ("١٢٣٤٥", false),
    ] {
        assert_eq!(
            check(
                I::SellerPostcode,
                &address(&format!("<cbc:PostalZone>{value}</cbc:PostalZone>"))
            )
            .unwrap(),
            [expected]
        );
    }
    for (value, expected) in [("1234", true), ("123", false), (" 1234", false)] {
        assert_eq!(
            check(
                I::SellerBuilding,
                &address(&format!("<cbc:BuildingNumber>{value}</cbc:BuildingNumber>"))
            )
            .unwrap(),
            [expected]
        );
    }
}

#[test]
fn seller_context_checks_global_buyer_street_including_duplicates() {
    let seller = party("Supplier", "<cac:PostalAddress/>");
    assert_eq!(check(I::BuyerAdditionalStreet, &seller).unwrap(), [true]);
    let buyer = party(
        "Customer",
        &format!(
            "<cac:PostalAddress><cbc:AdditionalStreetName>{}</cbc:AdditionalStreetName></cac:PostalAddress>",
            "x".repeat(128)
        ),
    );
    assert_eq!(
        check(I::BuyerAdditionalStreet, &(seller.clone() + &buyer)).unwrap(),
        [false]
    );
    assert_eq!(
        check(I::BuyerAdditionalStreet, &(seller + &buyer + &buyer)).unwrap_err(),
        FailureKind::Cardinality
    );
}

#[test]
fn vat_identifiers_use_exact_digits_and_different_presence_gates() {
    for (value, expected) in [
        ("300000000000003", true),
        ("300000000000002", false),
        ("30000000000003", false),
        (" 300000000000003", false),
        ("", false),
    ] {
        let tax = format!(
            "<cac:PartyTaxScheme><cbc:CompanyID>{value}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>"
        );
        assert_eq!(
            check(I::SellerVat, &party("Supplier", &tax)).unwrap(),
            [expected]
        );
        assert_eq!(
            check(I::BuyerVat, &party("Customer", &tax)).unwrap(),
            [expected || value.is_empty()]
        );
    }
    assert!(check(I::SellerVat, &party("Supplier", "<cac:PartyTaxScheme><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>")).unwrap().is_empty());
}

#[test]
fn buyer_phone_and_contact_bounds_use_all_matching_contacts() {
    for (phone, expected) in [
        ("01234", true),
        ("+1234", true),
        ("0123", false),
        ("12345", false),
        ("+123456789012345", true),
        ("+1234567890123456", false),
        ("", true),
    ] {
        let body = party(
            "Customer",
            &format!("<cac:Contact><cbc:Telephone>{phone}</cbc:Telephone></cac:Contact>"),
        );
        assert_eq!(check(I::BuyerPhone, &body).unwrap(), [expected]);
    }
    for (rule, field) in [(I::ContactName, "Name"), (I::ContactNote, "Note")] {
        for (len, expected) in [(0, true), (1000, true), (1001, false)] {
            let body = party(
                "Customer",
                &format!(
                    "<cac:Contact><cbc:{field}>{}</cbc:{field}></cac:Contact>",
                    "ع".repeat(len)
                ),
            );
            assert_eq!(check(rule, &body).unwrap(), [expected]);
        }
    }
}
