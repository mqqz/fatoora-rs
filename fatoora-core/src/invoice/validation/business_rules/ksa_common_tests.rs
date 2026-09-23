use super::{
    FailureKind, Limits,
    ksa_common::KsaCommonCheck as C,
    xml::{self, XmlView},
};

fn check(rule: C, body: &str) -> Result<Vec<bool>, FailureKind> {
    let input = format!(
        "<Invoice xmlns='{}' xmlns:cac='{}' xmlns:cbc='{}' xmlns:ext='urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2' xmlns:sig='urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2' xmlns:sac='urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2' xmlns:sbc='urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2'>{body}</Invoice>",
        xml::UBL,
        xml::CAC,
        xml::CBC
    );
    let xml = XmlView::parse(&input, &Limits::default())?;
    rule.contexts(&xml)
        .into_iter()
        .map(|node| rule.passes(&xml, node))
        .collect()
}
fn reference(id: &str, value: &str, mime: &str) -> String {
    format!(
        "<cac:AdditionalDocumentReference><cbc:ID>{id}</cbc:ID><cac:Attachment><cbc:EmbeddedDocumentBinaryObject mimeCode='{mime}'>{value}</cbc:EmbeddedDocumentBinaryObject></cac:Attachment></cac:AdditionalDocumentReference>"
    )
}
fn supplier(fields: &str) -> String {
    format!(
        "<cac:AccountingSupplierParty><cac:Party>{fields}</cac:Party></cac:AccountingSupplierParty>"
    )
}
fn buyer(fields: &str) -> String {
    format!(
        "<cac:AccountingCustomerParty><cac:Party>{fields}</cac:Party></cac:AccountingCustomerParty>"
    )
}
fn simplified(body: &str) -> String {
    format!("<cbc:InvoiceTypeCode name='0200000'>388</cbc:InvoiceTypeCode>{body}")
}

#[test]
fn optional_reference_lengths_are_scalar_unicode_character_counts() {
    for (rule, element) in [
        (C::OrderReferenceLength, "OrderReference"),
        (C::ContractReferenceLength, "ContractDocumentReference"),
    ] {
        assert_eq!(check(rule, "").unwrap(), [true]);
        for (length, expected) in [(0, true), (127, true), (128, false)] {
            assert_eq!(
                check(
                    rule,
                    &format!(
                        "<cac:{element}><cbc:ID>{}</cbc:ID></cac:{element}>",
                        "ع".repeat(length)
                    )
                )
                .unwrap(),
                [expected]
            );
        }
        assert_eq!(
            check(
                rule,
                &format!("<cac:{element}><cbc:ID/><cbc:ID/></cac:{element}>")
            )
            .unwrap_err(),
            FailureKind::Cardinality
        );
    }
}
#[test]
fn uuid_uses_xpath_word_categories_and_only_a_start_anchor() {
    for (value, valid) in [
        ("abc", true),
        ("ع", true),
        ("💰", true),
        ("-", true),
        (".", true),
        ("a! trailing", true),
        ("", false),
        ("_abc", false),
        (" abc", false),
    ] {
        assert_eq!(
            check(C::Uuid, &format!("<cbc:UUID>{value}</cbc:UUID>")).unwrap(),
            [valid],
            "{value}"
        );
    }
    assert_eq!(check(C::Uuid, "").unwrap(), [false]);
    assert_eq!(
        check(C::Uuid, "<cbc:UUID>a</cbc:UUID><cbc:UUID>b</cbc:UUID>").unwrap_err(),
        FailureKind::Cardinality
    );
}
#[test]
fn qr_filters_keep_raw_identifier_and_normalized_identifier_distinct() {
    assert_eq!(check(C::QrReference, "").unwrap(), [true]);
    for (id, value, mime, valid) in [
        ("QR", "value", "text/plain", true),
        (" QR ", "value", "text/plain", false),
        ("QR", " ", "text/plain", false),
        ("QR", "value", " text/plain ", true),
        ("QR", "value", "text/xml", false),
    ] {
        assert_eq!(
            check(C::QrReference, &simplified(&reference(id, value, mime))).unwrap(),
            [valid]
        );
    }
    for (value, valid) in [
        ("".to_string(), false),
        (" ".into(), true),
        ("ع".repeat(1000), true),
        ("ع".repeat(1001), false),
    ] {
        assert_eq!(
            check(C::QrLength, &reference(" QR ", &value, "text/plain")).unwrap(),
            [valid]
        );
    }
    assert_eq!(check(C::QrLength, "").unwrap(), [true]);
    assert_eq!(
        check(
            C::QrLength,
            &(reference("QR", "a", "text/plain") + &reference("QR", "b", "text/plain"))
        )
        .unwrap_err(),
        FailureKind::Cardinality
    );
}
#[test]
fn counter_uses_any_reference_uuid_and_an_empty_numeric_string_is_accepted() {
    let icv =
        "<cac:AdditionalDocumentReference><cbc:ID> ICV </cbc:ID></cac:AdditionalDocumentReference>";
    assert_eq!(check(C::InvoiceCounter, icv).unwrap(), [false]);
    let elsewhere = "<cac:AdditionalDocumentReference><cbc:ID>other</cbc:ID><cbc:UUID>123</cbc:UUID></cac:AdditionalDocumentReference>";
    assert_eq!(
        check(C::InvoiceCounter, &(icv.to_owned() + elsewhere)).unwrap(),
        [true]
    );
    assert_eq!(check(C::InvoiceCounter, elsewhere).unwrap(), [false]);
    for (value, valid) in [("", true), ("123", true), (" 123", false), ("١٢٣", false)] {
        assert_eq!(check(C::CounterDigits,&format!("<cac:AdditionalDocumentReference><cbc:UUID>{value}</cbc:UUID></cac:AdditionalDocumentReference>")).unwrap(),[valid]);
    }
    assert_eq!(check(C::CounterDigits, "").unwrap(), [true]);
    assert_eq!(
        check(C::CounterDigits, &(elsewhere.to_owned() + elsewhere)).unwrap_err(),
        FailureKind::Cardinality
    );
}
#[test]
fn contract_required_only_for_the_global_ninth_transaction_flag() {
    assert_eq!(check(C::ContractReference, "").unwrap(), [true]);
    let trigger = "<cac:InvoiceLine><cbc:InvoiceTypeCode name='020000001'/></cac:InvoiceLine>";
    assert_eq!(check(C::ContractReference, trigger).unwrap(), [false]);
    for (value, valid) in [(" ", false), ("X", true)] {
        assert_eq!(check(C::ContractReference,&format!("{trigger}<cac:ContractDocumentReference><cbc:ID>{value}</cbc:ID></cac:ContractDocumentReference>")).unwrap(),[valid]);
    }
    assert_eq!(
        check(
            C::ContractReference,
            &trigger.replace("020000001", "02000001")
        )
        .unwrap(),
        [true]
    );
}
#[test]
fn party_rules_preserve_independent_general_comparisons_and_scheme_membership() {
    let tax = |id: &str| {
        format!(
            "<cac:PartyTaxScheme><cbc:CompanyID>{id}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>"
        )
    };
    assert_eq!(
        check(
            C::DifferentVatNumbers,
            &(supplier(&tax("1")) + &buyer(&tax("1")))
        )
        .unwrap(),
        [false]
    );
    assert_eq!(
        check(
            C::DifferentVatNumbers,
            &(supplier(&tax("1")) + &buyer(&tax("2")))
        )
        .unwrap(),
        [true]
    );
    assert_eq!(
        check(
            C::DifferentVatNumbers,
            &(supplier(&(tax("1") + &tax(""))) + &buyer(&(tax("2") + &tax(""))))
        )
        .unwrap(),
        [false]
    );
    assert_eq!(check(C::SellerVat, &supplier(&tax("1"))).unwrap(), [true]);
    assert_eq!(check(C::SellerVat, &supplier(&tax(""))).unwrap(), [false]);
    assert_eq!(
        check(C::SellerVat, &supplier(&tax("1").replace(">VAT<", ">vat<"))).unwrap(),
        [false]
    );
    for (scheme, valid) in [
        ("CRN", true),
        (" CRN ", true),
        ("CRN MOM", true),
        ("crn", false),
        ("CR", false),
    ] {
        assert_eq!(check(C::SellerScheme,&supplier(&format!("<cac:PartyIdentification><cbc:ID schemeID='{scheme}'/></cac:PartyIdentification>"))).unwrap(),[valid]);
    }
    assert_eq!(check(C::SellerScheme,&supplier("<cac:PartyIdentification><cbc:ID schemeID='CRN'/><cbc:ID/></cac:PartyIdentification>")).unwrap_err(),FailureKind::Cardinality);
}
#[test]
fn pih_and_tax_currency_presence_do_not_trim_binary_or_currency_values() {
    for rule in [C::PreviousHash, C::PreviousHashAttachment] {
        for (value, mime, valid) in [
            ("x", "text/plain", true),
            (" ", " text/plain ", true),
            ("", "text/plain", false),
            ("x", "text/xml", false),
        ] {
            assert_eq!(
                check(rule, &reference(" PIH ", value, mime)).unwrap(),
                [valid]
            );
        }
    }
    assert_eq!(check(C::PreviousHash, "").unwrap(), [false]);
    for (body, valid) in [
        ("", false),
        ("<cbc:TaxCurrencyCode/>", false),
        ("<cbc:TaxCurrencyCode> </cbc:TaxCurrencyCode>", true),
    ] {
        assert_eq!(check(C::TaxCurrency, body).unwrap(), [valid]);
    }
}
#[test]
fn charge_reason_codes_use_unpadded_substring_membership_and_skip_price_children() {
    let adjustment = |indicator: &str, code: &str| {
        format!(
            "<cac:AllowanceCharge><cbc:ChargeIndicator>{indicator}</cbc:ChargeIndicator><cbc:AllowanceChargeReasonCode>{code}</cbc:AllowanceChargeReasonCode></cac:AllowanceCharge>"
        )
    };
    for (code, valid) in [
        ("", true),
        ("AAA", true),
        ("AA", true),
        ("CAPCAQ", true),
        ("BAD", false),
    ] {
        assert_eq!(
            check(C::ChargeReasonCode, &adjustment("true", code)).unwrap(),
            [valid]
        );
    }
    assert_eq!(
        check(C::ChargeReasonCode, &adjustment("false", "BAD")).unwrap(),
        [true]
    );
    assert_eq!(
        check(
            C::ChargeReasonCode,
            &format!("<cac:Price>{}</cac:Price>", adjustment("true", "BAD"))
        )
        .unwrap(),
        [true]
    );
    assert_eq!(
        check(C::ChargeReasonCode, &adjustment("False", "AAA")).unwrap_err(),
        FailureKind::InvalidBoolean
    );
}
#[test]
fn education_exemption_requires_a_global_national_buyer_identifier() {
    let category = "<cac:TaxTotal><cac:TaxSubtotal><cac:TaxCategory><cbc:TaxExemptionReasonCode>VATEX-SA-EDU</cbc:TaxExemptionReasonCode></cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal>";
    assert_eq!(check(C::NationalBuyer, category).unwrap(), [false]);
    assert_eq!(
        check(
            C::NationalBuyer,
            &(category.to_owned()
                + &buyer(
                    "<cac:PartyIdentification><cbc:ID schemeID='NAT'/></cac:PartyIdentification>"
                ))
        )
        .unwrap(),
        [true]
    );
    assert!(
        check(
            C::NationalBuyer,
            &category.replace("VATEX-SA-EDU", "VATEX-SA-32")
        )
        .unwrap()
        .is_empty()
    );
}
#[test]
fn signature_attachment_rules_keep_global_paths_and_pih_template_suppression() {
    let extension = "<ext:UBLExtensions><ext:UBLExtension><ext:ExtensionContent><sig:UBLDocumentSignatures><sac:SignatureInformation><cbc:ID>urn:oasis:names:specification:ubl:signature:1</cbc:ID><sbc:ReferencedSignatureID>urn:oasis:names:specification:ubl:signature:Invoice</sbc:ReferencedSignatureID></sac:SignatureInformation></sig:UBLDocumentSignatures></ext:ExtensionContent></ext:UBLExtension></ext:UBLExtensions>";
    let signature = "<cac:Signature><cbc:ID>urn:oasis:names:specification:ubl:signature:Invoice</cbc:ID><cbc:SignatureMethod>urn:oasis:names:specification:ubl:dsig:enveloped:xades</cbc:SignatureMethod></cac:Signature>";
    for rule in [
        C::SignatureInformation,
        C::SignatureReference,
        C::SignatureMethod,
    ] {
        assert_eq!(
            check(rule, &simplified(&reference("QR", "x", "text/plain"))).unwrap(),
            [false]
        );
        assert_eq!(
            check(
                rule,
                &simplified(&(reference("QR", "x", "text/plain") + extension + signature))
            )
            .unwrap(),
            [true]
        );
        assert_eq!(
            check(rule, &simplified(&reference("PIH", "x", "text/plain"))).unwrap(),
            [true]
        );
        assert_eq!(
            check(rule, &reference("QR", "x", "text/plain")).unwrap(),
            [true]
        );
    }
}
#[test]
fn actual_delivery_and_buyer_name_use_different_whitespace_gates() {
    assert_eq!(
        check(
            C::ActualDeliveryDate,
            "<cac:Delivery><cbc:LatestDeliveryDate/></cac:Delivery>"
        )
        .unwrap(),
        [false]
    );
    for (value, valid) in [(" ", false), ("2026-09-23", true)] {
        assert_eq!(check(C::ActualDeliveryDate,&format!("<cac:Delivery><cbc:LatestDeliveryDate/><cbc:ActualDeliveryDate>{value}</cbc:ActualDeliveryDate></cac:Delivery>")).unwrap(),[valid]);
    }
    assert_eq!(check(C::BuyerName, &buyer("")).unwrap(), [true]);
    for (value, valid) in [("", false), (" ", true), ("name", true)] {
        assert_eq!(check(C::BuyerName,&format!("<cbc:InvoiceTypeCode name='0100000'/>{}",buyer(&format!("<cac:PartyLegalEntity><cbc:RegistrationName>{value}</cbc:RegistrationName></cac:PartyLegalEntity>")))).unwrap(),[valid]);
    }
}

#[test]
fn root_patterns_require_the_ubl_document_name_and_namespace() {
    for (namespace, root, expected) in [
        (xml::UBL, "Invoice", true),
        (xml::CREDIT_NOTE, "CreditNote", true),
        (xml::UBL, "CreditNote", false),
        ("urn:other", "Invoice", false),
    ] {
        let xml = XmlView::parse(
            &format!(
                "<{root} xmlns='{namespace}' xmlns:cac='{}'><cac:AllowanceCharge/></{root}>",
                xml::CAC
            ),
            &Limits::default(),
        )
        .unwrap();
        for check in [C::Uuid, C::TaxCurrency, C::ChargeReasonCode] {
            assert_eq!(check.contexts(&xml).is_empty(), !expected);
        }
    }
}
