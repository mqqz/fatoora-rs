use diplomat_runtime::DiplomatWrite;
use fatoora_ffi::common::ffi::BindingError;
use fatoora_ffi::invoice::ffi::{Address, FinalizedInvoice, InvoiceBuilder};

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
    let mut b = ok(InvoiceBuilder::new(0, 1, None, None, None, None));
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

fn written(f: impl FnOnce(&mut DiplomatWrite)) -> String {
    struct Writer(*mut DiplomatWrite);
    impl Drop for Writer {
        fn drop(&mut self) {
            unsafe {
                diplomat_runtime::diplomat_buffer_write_destroy(self.0);
            }
        }
    }
    let out = Writer(diplomat_runtime::diplomat_buffer_write_create(0));
    unsafe {
        f(&mut *out.0);
        std::str::from_utf8((*out.0).as_bytes()).unwrap().to_owned()
    }
}
