use fatoora_core::invoice::CountryCode;
use fatoora_core::invoice::{
    Address, InvoiceBuilder, InvoiceError, InvoiceField, InvoiceSubType, InvoiceType, LineItem,
    ValidationKind, VatCategory,
};
use fatoora_core::invoice::{OtherId, Party, SellerRole};

fn dummy_seller() -> Party<SellerRole> {
    Party::<SellerRole>::new(
        "Acme Inc".into(),
        Address {
            country_code: CountryCode::parse("SAU").expect("country code"),
            city: "Riyadh".into(),
            street: "King Fahd".into(),
            additional_street: None,
            building_number: "1234".into(),
            additional_number: Some("5678".into()),
            postal_code: "12222".into(),
            subdivision: None,
            district: Some("Olaya".into()),
        },
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller")
}

#[test]
fn build_reports_missing_required_fields() {
    let issue_datetime = "2024-01-01T12:30:00Z";
    let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified));
    builder
        .set_id("  ")
        .set_uuid("")
        .set_issue_datetime(issue_datetime)
        .set_currency("SAR")
        .set_previous_invoice_hash("")
        .set_invoice_counter(0)
        .set_seller(dummy_seller())
        .set_payment_means_code("   ")
        .set_vat_category(VatCategory::Standard);

    let err = builder.build().expect_err("expected validation error");
    let InvoiceError::Validation(validation) = err else {
        panic!("expected validation error");
    };

    let fields: Vec<_> = validation.issues().iter().map(|i| i.field()).collect();
    assert!(fields.contains(&InvoiceField::Id));
    assert!(fields.contains(&InvoiceField::Uuid));
    assert!(fields.contains(&InvoiceField::PreviousInvoiceHash));
    assert!(fields.contains(&InvoiceField::PaymentMeansCode));
    assert!(fields.contains(&InvoiceField::LineItems));
}

#[test]
fn build_reports_invalid_line_items() {
    let issue_datetime = "2024-01-01T12:30:00Z";
    let line_item = LineItem::from_totals("", -1.0, "", -1.0, -1.0, 15.0, VatCategory::Standard);
    let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified));
    builder
        .set_id("INV-1")
        .set_uuid("uuid-1")
        .set_issue_datetime(issue_datetime)
        .set_currency("SAR")
        .set_previous_invoice_hash("hash")
        .set_invoice_counter(0)
        .set_seller(dummy_seller())
        .set_payment_means_code("10")
        .set_vat_category(VatCategory::Standard)
        .add_line_item(line_item);

    let err = builder.build().expect_err("expected validation error");
    let InvoiceError::Validation(validation) = err else {
        panic!("expected validation error");
    };

    let mut has_description = false;
    let mut has_unit_code = false;
    let mut has_quantity = false;
    let mut has_unit_price = false;
    let mut has_total_amount = false;
    let mut has_vat_amount = false;

    for issue in validation.issues() {
        if issue.line_item_index() != Some(0) {
            continue;
        }
        match (issue.field(), issue.kind()) {
            (InvoiceField::LineItemDescription, ValidationKind::Empty) => {
                has_description = true;
            }
            (InvoiceField::LineItemUnitCode, ValidationKind::Empty) => {
                has_unit_code = true;
            }
            (InvoiceField::LineItemQuantity, ValidationKind::OutOfRange) => {
                has_quantity = true;
            }
            (InvoiceField::LineItemUnitPrice, ValidationKind::OutOfRange) => {
                has_unit_price = true;
            }
            (InvoiceField::LineItemTotalAmount, ValidationKind::OutOfRange) => {
                has_total_amount = true;
            }
            (InvoiceField::LineItemVatAmount, ValidationKind::OutOfRange) => {
                has_vat_amount = true;
            }
            _ => {}
        }
    }

    assert!(has_description);
    assert!(has_unit_code);
    assert!(has_quantity);
    assert!(has_unit_price);
    assert!(has_total_amount);
    assert!(has_vat_amount);
}

#[test]
fn line_item_try_from_parts_reports_mismatch() {
    let err = LineItem::try_from_parts(
        "Item",
        1.0,
        "PCE",
        100.0,
        100.0,
        15.0,
        10.0,
        VatCategory::Standard,
    )
    .expect_err("expected mismatch error");

    assert!(err.issues().iter().any(|issue| {
        issue.field() == InvoiceField::LineItemVatAmount && issue.kind() == ValidationKind::Mismatch
    }));
}

#[test]
fn credit_note_missing_required_fields_reports_issues() {
    let mut builder = InvoiceBuilder::new(InvoiceType::CreditNote(
        InvoiceSubType::Standard,
        fatoora_core::invoice::OriginalInvoiceRef::new("INV-ORIG"),
        "reason".into(),
    ));
    builder
        .set_id(" ")
        .set_uuid("")
        .set_issue_datetime("")
        .set_currency("")
        .set_previous_invoice_hash("")
        .set_payment_means_code(" ")
        .set_vat_category(VatCategory::Standard);

    let err = builder.build().expect_err("expected validation error");
    let InvoiceError::Validation(validation) = err else {
        panic!("expected validation error");
    };

    let fields: Vec<_> = validation.issues().iter().map(|i| i.field()).collect();
    assert!(fields.contains(&InvoiceField::Id));
    assert!(fields.contains(&InvoiceField::Uuid));
    assert!(fields.contains(&InvoiceField::IssueDateTime));
    assert!(fields.contains(&InvoiceField::Currency));
    assert!(fields.contains(&InvoiceField::PreviousInvoiceHash));
    assert!(fields.contains(&InvoiceField::PaymentMeansCode));
    assert!(fields.contains(&InvoiceField::LineItems));
    assert!(fields.contains(&InvoiceField::Seller));
    assert!(fields.contains(&InvoiceField::InvoiceCounter));
}

#[test]
fn credit_note_invalid_line_item_reports_issues() {
    let issue_datetime = "2024-01-01T12:30:00Z";
    let line_item = LineItem::from_totals("", -1.0, "", -1.0, -1.0, 15.0, VatCategory::Standard);
    let mut builder = InvoiceBuilder::new(InvoiceType::CreditNote(
        InvoiceSubType::Simplified,
        fatoora_core::invoice::OriginalInvoiceRef::new("INV-ORIG"),
        "reason".into(),
    ));
    builder
        .set_id("CR-1")
        .set_uuid("uuid-cr-1")
        .set_issue_datetime(issue_datetime)
        .set_currency("SAR")
        .set_previous_invoice_hash("hash")
        .set_invoice_counter(0)
        .set_seller(dummy_seller())
        .set_payment_means_code("10")
        .set_vat_category(VatCategory::Standard)
        .add_line_item(line_item);

    let err = builder.build().expect_err("expected validation error");
    let InvoiceError::Validation(validation) = err else {
        panic!("expected validation error");
    };

    assert!(validation.issues().iter().any(|issue| {
        issue.field() == InvoiceField::LineItemQuantity
            && issue.kind() == ValidationKind::OutOfRange
    }));
    assert!(validation.issues().iter().any(|issue| {
        issue.field() == InvoiceField::LineItemUnitPrice
            && issue.kind() == ValidationKind::OutOfRange
    }));
    assert!(validation.issues().iter().any(|issue| {
        issue.field() == InvoiceField::LineItemTotalAmount
            && issue.kind() == ValidationKind::OutOfRange
    }));
    assert!(validation.issues().iter().any(|issue| {
        issue.field() == InvoiceField::LineItemVatAmount
            && issue.kind() == ValidationKind::OutOfRange
    }));
}
