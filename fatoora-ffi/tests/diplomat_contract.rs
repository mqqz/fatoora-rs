mod support;
use fatoora_ffi::common::ffi::BindingError;
use fatoora_ffi::invoice::ffi::{Address, FinalizedInvoice, InvoiceBuilder};
use support::written;

fn ok<T>(result: Result<T, Box<BindingError>>) -> T {
    result.unwrap_or_else(|e| {
        panic!(
            "binding error {}: {}",
            e.code(),
            written(|out| e.message(out))
        )
    })
}

#[test]
fn exact_decimals_and_consumption() {
    let mut b = builder();
    ok(b.add_line_item(b"Item", b"3", b"PCE", b"0.3333", b"15", 1));
    let invoice = ok(b.build());
    let xml = written(|out| ok(invoice.xml(out)));
    assert!(xml.contains(">0.3333</cbc:PriceAmount>"));
    assert!(xml.contains(">1.15</cbc:TaxInclusiveAmount>"));
    let parsed = ok(FinalizedInvoice::from_xml(xml.as_bytes()));
    assert_eq!(
        written(|out| ok(ok(parsed.totals()).tax_inclusive(out))),
        "1.15"
    );
    let line = ok(ok(parsed.data()).line_item(0));
    assert_eq!(written(|out| ok(line.unit_price(out))), "0.3333");
    assert_eq!(written(|out| ok(line.quantity(out))), "3");
    assert_eq!(b.build().err().unwrap().code(), 1);
    assert!(b.set_id(b"reuse").is_err());
}

#[test]
fn rejected_inputs_preserve_builder_and_structured_error() {
    let mut b = builder();
    let error = b
        .add_line_item(b"Item", b"1", b"PCE", b"invalid", b"15", 1)
        .err()
        .unwrap();
    assert_eq!(error.code(), 1);
    let details: serde_json::Value =
        serde_json::from_str(&written(|out| error.details_json(out))).unwrap();
    assert!(details["type"].is_string());
    for id in [&b"bad\0id"[..], &[0xff][..]] {
        assert_eq!(b.set_id(id).err().unwrap().code(), 1);
    }
    assert!(b.set_vat_category(255).is_err());
    assert!(b.flags(0x80).is_err());
    assert!(
        b.add_line_item(b"Item", b"1", b"PCE", b"1", b"15", 255)
            .is_err()
    );
    ok(b.add_line_item(b"Item", b"1", b"PCE", b"1.005", b"15", 1));
    let invoice = ok(b.build());
    let data = ok(invoice.data());
    assert_eq!(written(|out| ok(data.id(out))), "INV-1");
    assert_eq!(data.line_items_len(), 1);
    assert!(data.line_item(1).is_err());
    assert!(data.line_item(usize::MAX).is_err());
}

#[test]
fn failed_build_also_consumes_builder() {
    let mut b = builder();
    assert!(b.build().is_err());
    assert_eq!(b.build().err().unwrap().code(), 1);
    assert!(b.set_id(b"again").is_err());
}

#[test]
fn enum_values_and_credit_note_inputs_are_checked() {
    assert!(InvoiceBuilder::new(255, 1, None, None, None, None).is_err());
    assert!(InvoiceBuilder::new(0, 255, None, None, None, None).is_err());
    assert!(InvoiceBuilder::new(2, 1, None, None, None, None).is_err());
    assert!(InvoiceBuilder::new(3, 1, Some(b"INV-0"), None, None, None).is_err());
    assert!(
        InvoiceBuilder::new(
            2,
            1,
            Some(b"INV-0"),
            None,
            Some(b"not-a-date"),
            Some(b"Correction")
        )
        .is_err()
    );
    assert!(
        InvoiceBuilder::new(
            2,
            1,
            Some(b"INV-0"),
            None,
            Some(b"2023-11-13"),
            Some(b"Correction")
        )
        .is_ok()
    );
}

#[test]
fn child_snapshots_survive_parent_drop() {
    let mut b = builder();
    ok(b.add_line_item(b"Item", b"1", b"PCE", b"100", b"15", 1));
    let invoice = ok(b.build());
    let data = ok(invoice.data());
    let line = ok(data.line_item(0));
    let seller = ok(data.seller());
    let address = ok(seller.address());
    drop(invoice);
    drop(data);
    drop(seller);
    assert_eq!(written(|out| ok(line.description(out))), "Item");
    assert_eq!(written(|out| ok(address.city(out))), "Riyadh");
}

fn builder() -> Box<InvoiceBuilder> {
    configured(ok(InvoiceBuilder::new(0, 1, None, None, None, None)))
}

fn configured(mut b: Box<InvoiceBuilder>) -> Box<InvoiceBuilder> {
    ok(b.set_id(b"INV-1"));
    ok(b.set_uuid(b"8e6000cf-1a98-4174-b3e7-b5d5954bc10d"));
    ok(b.set_issue_datetime(b"2024-01-01T12:30:00Z"));
    ok(b.set_previous_invoice_hash(b"hash"));
    ok(b.set_invoice_counter(1));
    ok(b.set_currency(b"SAR"));
    ok(b.set_payment_means_code(b"10"));
    ok(b.set_vat_category(1));
    let address = ok(Address::new(
        b"SAU",
        b"Riyadh",
        b"King Fahd",
        b"1234",
        b"12222",
        None,
        None,
        Some(b"Olaya"),
    ));
    ok(b.set_seller(
        b"Seller",
        &address,
        b"399999999900003",
        Some(b"7003339333"),
        Some(b"CRN"),
    ));
    b
}

#[test]
fn rejected_setters_leave_previous_values_and_totals_intact() {
    let mut b = builder();
    ok(b.set_note(b"ar", "خصم & خدمة".as_bytes()));
    ok(b.set_allowance(b"Discount", b"10"));
    ok(b.invoice_level_charge(b"5"));
    assert!(b.set_issue_datetime(b"2024-02-30T12:00:00Z").is_err());
    assert!(b.set_currency(b"NOT-CURRENCY").is_err());
    assert!(b.set_note(b"ar", b"bad\0note").is_err());
    assert!(b.set_allowance(b"overwrite", b"NaN").is_err());
    assert!(b.invoice_level_charge(b"Infinity").is_err());
    assert!(b.invoice_level_discount(b"invalid").is_err());
    ok(b.add_line_item(b"Item", b"2", b"PCE", b"50", b"15", 1));
    let invoice = ok(b.build());
    let data = ok(invoice.data());
    assert_eq!(
        written(|out| ok(data.issue_datetime(out))),
        "2024-01-01T12:30:00Z"
    );
    assert_eq!(written(|out| ok(data.currency(out))), "SAR");
    assert_eq!(
        written(|out| ok(ok(data.allowance_reason()).unwrap().value(out))),
        "Discount"
    );
    let note = ok(data.note()).unwrap();
    assert_eq!(written(|out| ok(note.language(out))), "ar");
    assert_eq!(written(|out| ok(note.text(out))), "خصم & خدمة");
    let totals = ok(invoice.totals());
    // Independent arithmetic: (2 * 50 - 10 + 5) * 1.15 = 109.25.
    assert_eq!(written(|out| ok(totals.line_extension(out))), "100");
    assert_eq!(written(|out| ok(totals.allowance_total(out))), "10");
    assert_eq!(written(|out| ok(totals.charge_total(out))), "5");
    assert_eq!(written(|out| ok(totals.taxable_amount(out))), "95");
    assert_eq!(written(|out| ok(totals.tax_amount(out))), "14.25");
    assert_eq!(written(|out| ok(totals.payable_amount(out))), "109.25");
    let xml = written(|out| ok(invoice.xml(out)));
    assert!(xml.contains("خصم &amp; خدمة"));
    let parsed = ok(FinalizedInvoice::from_xml(xml.as_bytes()));
    assert_eq!(
        written(|out| ok(ok(ok(parsed.data()).note()).unwrap().text(out))),
        "خصم & خدمة"
    );
}

#[test]
fn buyer_optional_fields_and_owned_snapshots_preserve_absent_vs_empty() {
    for vat in [None, Some(&b"399999999900003"[..])] {
        let mut b = builder();
        let address = ok(Address::new(
            b"SAU",
            b"Riyadh",
            b"Street",
            b"1234",
            b"12222",
            Some(b""),
            None,
            Some("حي".as_bytes()),
        ));
        ok(b.set_buyer("مشتري".as_bytes(), &address, vat, Some(b"buyer-id"), None));
        // A failed replacement must leave the existing buyer intact.
        assert!(
            b.set_buyer(b"replacement", &address, Some(b"invalid\0vat"), None, None)
                .is_err()
        );
        drop(address);
        ok(b.add_line_item(b"Item", b"1", b"PCE", b"100", b"15", 1));
        let invoice = ok(b.build());
        let data = ok(invoice.data());
        let buyer = ok(data.buyer()).unwrap();
        let address = ok(buyer.address());
        let id = ok(buyer.other_id()).unwrap();
        let vat_id = ok(buyer.vat_id());
        assert_eq!(written(|out| ok(buyer.name(out))), "مشتري");
        drop(invoice);
        drop(data);
        drop(buyer);
        assert_eq!(vat_id.is_some(), vat.is_some());
        if let Some(vat_id) = vat_id {
            assert_eq!(written(|out| ok(vat_id.value(out))), "399999999900003");
        }
        assert_eq!(written(|out| ok(id.value(out))), "buyer-id");
        assert!(ok(id.scheme()).is_none());
        assert_eq!(
            written(|out| ok(ok(address.additional_street()).unwrap().value(out))),
            ""
        );
        assert!(ok(address.additional_number()).is_none());
        assert_eq!(
            written(|out| ok(ok(address.district()).unwrap().value(out))),
            "حي"
        );
    }
}

#[test]
fn vat_category_mapping_preserves_zero_tax_categories() {
    for (category, xml_code) in [(0, "E"), (1, "S"), (2, "Z"), (3, "O")] {
        let mut b = builder();
        ok(b.set_vat_category(category));
        ok(b.add_line_item(
            b"Item",
            b"1",
            b"PCE",
            b"100",
            if category == 1 { b"15" } else { b"0" },
            category,
        ));
        let invoice = ok(b.build());
        let data = ok(invoice.data());
        assert_eq!(data.vat_category(), category);
        assert_eq!(ok(data.line_item(0)).vat_category(), category);
        assert_eq!(
            written(|out| ok(ok(invoice.totals()).tax_amount(out))),
            if category == 1 { "15" } else { "0" }
        );
        let xml = written(|out| ok(invoice.xml(out)));
        assert!(xml.contains(&format!(">{xml_code}</cbc:ID>")));
        assert!(ok(data.buyer()).is_none());
        assert!(ok(data.note()).is_none());
        assert!(ok(data.original_invoice_ref()).is_none());
        assert!(ok(data.original_invoice_reason()).is_none());
    }
}

#[test]
fn credit_and_debit_notes_keep_original_reference_after_parent_drop() {
    for kind in [2, 3] {
        for optional in [false, true] {
            let mut b = configured(ok(InvoiceBuilder::new(
                kind,
                1,
                Some(b"INV-0"),
                optional.then_some(b"old-uuid"),
                optional.then_some(b"2023-11-13"),
                Some("تصحيح".as_bytes()),
            )));
            ok(b.add_line_item(b"Item", b"1", b"PCE", b"100", b"15", 1));
            let invoice = ok(b.build());
            let data = ok(invoice.data());
            assert_eq!(data.invoice_type_kind(), kind);
            assert_eq!(data.invoice_sub_type(), 1);
            let reference = ok(data.original_invoice_ref()).unwrap();
            let reason = ok(data.original_invoice_reason()).unwrap();
            drop(invoice);
            drop(data);
            assert_eq!(written(|out| ok(reference.id(out))), "INV-0");
            assert_eq!(written(|out| ok(reason.value(out))), "تصحيح");
            let uuid = ok(reference.uuid());
            let date = ok(reference.issue_date());
            assert_eq!(uuid.is_some(), optional);
            assert_eq!(date.is_some(), optional);
            if optional {
                assert_eq!(written(|out| ok(uuid.unwrap().value(out))), "old-uuid");
                assert_eq!(written(|out| ok(date.unwrap().value(out))), "2023-11-13");
            }
        }
    }
}
