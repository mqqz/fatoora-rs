mod common;

use fatoora_core::invoice::{InvoiceBuilder, InvoiceSubType, InvoiceType, VatCategory};

#[test]
fn chained_builder_moves_owned_fields_into_invoice() {
    let source = common::dummy_finalized_invoice();
    let id = String::from("INV-owned");
    let id_ptr = id.as_ptr();
    let item = source.data().line_items()[0].clone();
    let description_ptr = item.description().as_ptr();
    let invoice = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified))
        .id(id)
        .uuid("uuid-owned")
        .issue_datetime("2024-01-01T12:30:00Z")
        .currency("SAR")
        .previous_invoice_hash("hash")
        .invoice_counter(1)
        .seller(source.data().seller().clone())
        .payment_means_code("10")
        .vat_category(VatCategory::Standard)
        .line_item(item)
        .build()
        .unwrap();
    assert_eq!(invoice.data().id(), "INV-owned");
    assert_eq!(invoice.data().id().as_ptr(), id_ptr);
    assert_eq!(
        invoice.data().line_items()[0].description().as_ptr(),
        description_ptr
    );
}

#[test]
fn conditional_configuration_and_repeated_lines_keep_order() {
    let source = common::dummy_finalized_invoice();
    let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified))
        .id("INV-conditional")
        .uuid("uuid-conditional")
        .issue_datetime("2024-01-01T12:30:00Z")
        .currency("SAR")
        .previous_invoice_hash("hash")
        .invoice_counter(1)
        .seller(source.data().seller().clone())
        .payment_means_code("10")
        .vat_category(VatCategory::Standard);
    if let Some(id) = Some("INV-replaced") {
        builder = builder.id(id);
    }
    for description in ["first", "second"] {
        builder = builder.line_item(
            fatoora_core::invoice::LineItem::new(
                description,
                1.into(),
                "PCE",
                100.into(),
                15.into(),
                VatCategory::Standard,
            )
            .unwrap(),
        );
    }
    let invoice = builder.build().unwrap();
    assert_eq!(invoice.data().id(), "INV-replaced");
    assert_eq!(invoice.data().line_items()[0].description(), "first");
    assert_eq!(invoice.data().line_items()[1].description(), "second");
}
