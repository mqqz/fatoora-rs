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
    builder = builder
        .id("  ")
        .uuid("")
        .issue_datetime(issue_datetime)
        .currency("SAR")
        .previous_invoice_hash("")
        .invoice_counter(0)
        .seller(dummy_seller())
        .payment_means_code("   ")
        .vat_category(VatCategory::Standard);

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
    let line_item: LineItem = serde_json::from_value(serde_json::json!({
        "description":"", "quantity":"-1", "unit_code":"", "unit_price":"-1",
        "total_amount":"-1", "vat_rate":"15", "vat_amount":"-0.15", "vat_category":"Standard"
    }))
    .unwrap();
    let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified));
    builder = builder
        .id("INV-1")
        .uuid("uuid-1")
        .issue_datetime(issue_datetime)
        .currency("SAR")
        .previous_invoice_hash("hash")
        .invoice_counter(0)
        .seller(dummy_seller())
        .payment_means_code("10")
        .vat_category(VatCategory::Standard)
        .line_item(line_item);

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
        fatoora_core::Decimal::parse("1.0").unwrap(),
        "PCE",
        fatoora_core::Decimal::parse("100.0").unwrap(),
        fatoora_core::Decimal::parse("100.0").unwrap(),
        fatoora_core::Decimal::parse("15.0").unwrap(),
        fatoora_core::Decimal::parse("10.0").unwrap(),
        VatCategory::Standard,
    )
    .expect_err("expected mismatch error");

    let InvoiceError::Validation(err) = err else {
        panic!("expected validation error")
    };
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
    builder = builder
        .id(" ")
        .uuid("")
        .issue_datetime("")
        .currency("")
        .previous_invoice_hash("")
        .payment_means_code(" ")
        .vat_category(VatCategory::Standard);

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
    let line_item: LineItem = serde_json::from_value(serde_json::json!({
        "description":"", "quantity":"-1", "unit_code":"", "unit_price":"-1",
        "total_amount":"-1", "vat_rate":"15", "vat_amount":"-0.15", "vat_category":"Standard"
    }))
    .unwrap();

    let mut builder = InvoiceBuilder::new(InvoiceType::CreditNote(
        InvoiceSubType::Simplified,
        fatoora_core::invoice::OriginalInvoiceRef::new("INV-ORIG"),
        "reason".into(),
    ));
    builder = builder
        .id("CR-1")
        .uuid("uuid-cr-1")
        .issue_datetime(issue_datetime)
        .currency("SAR")
        .previous_invoice_hash("hash")
        .invoice_counter(0)
        .seller(dummy_seller())
        .payment_means_code("10")
        .vat_category(VatCategory::Standard)
        .line_item(line_item);

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
