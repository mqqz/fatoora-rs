use fatoora_core::invoice::{
    Address, InvoiceBuilder, InvoiceError, InvoiceField, InvoiceSubType, InvoiceType, LineItem,
    LineItemPartsFields, LineItemTotalsFields, RequiredInvoiceFields, ValidationKind, VatCategory,
};
use fatoora_core::invoice::{OtherId, Party, SellerRole};
use iso_currency::Currency;
use isocountry::CountryCode;

fn dummy_seller() -> Party<SellerRole> {
    Party::<SellerRole>::new(
        "Acme Inc".into(),
        Address {
            country_code: CountryCode::SAU,
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
    let issue_datetime = chrono::Utc::now();
    let builder = InvoiceBuilder::new(RequiredInvoiceFields {
        invoice_type: InvoiceType::Tax(InvoiceSubType::Simplified),
        id: "  ".into(),
        uuid: "".into(),
        issue_datetime,
        currency: Currency::SAR,
        previous_invoice_hash: "".into(),
        invoice_counter: 0,
        seller: dummy_seller(),
        line_items: Vec::new(),
        payment_means_code: "   ".into(),
        vat_category: VatCategory::Standard,
    });

    let err = builder.build().expect_err("expected validation error");
    let InvoiceError::Validation(validation) = err else {
        panic!("expected validation error");
    };

    let fields: Vec<_> = validation.issues.iter().map(|i| i.field).collect();
    assert!(fields.contains(&InvoiceField::Id));
    assert!(fields.contains(&InvoiceField::Uuid));
    assert!(fields.contains(&InvoiceField::PaymentMeansCode));
    assert!(fields.contains(&InvoiceField::LineItems));
}

#[test]
fn build_reports_invalid_line_items() {
    let issue_datetime = chrono::Utc::now();
    let line_item = LineItem::from_totals(LineItemTotalsFields {
            description: "".into(),
            quantity: -1.0,
            unit_code: "".into(),
            unit_price: -1.0,
            total_amount: -1.0,
            vat_rate: 15.0,
            vat_category: VatCategory::Standard,
        });
    let builder = InvoiceBuilder::new(RequiredInvoiceFields {
        invoice_type: InvoiceType::Tax(InvoiceSubType::Simplified),
        id: "INV-1".into(),
        uuid: "uuid-1".into(),
        issue_datetime,
        currency: Currency::SAR,
        previous_invoice_hash: "hash".into(),
        invoice_counter: 0,
        seller: dummy_seller(),
        line_items: vec![line_item],
        payment_means_code: "10".into(),
        vat_category: VatCategory::Standard,
    });

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

    for issue in &validation.issues {
        if issue.line_item_index != Some(0) {
            continue;
        }
        match (issue.field, issue.kind) {
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
    let err = LineItem::try_from_parts(LineItemPartsFields {
        description: "Item".into(),
        quantity: 1.0,
        unit_code: "PCE".into(),
        unit_price: 100.0,
        total_amount: 100.0,
        vat_rate: 15.0,
        vat_amount: 10.0,
        vat_category: VatCategory::Standard,
    })
    .expect_err("expected mismatch error");

    assert!(err.issues.iter().any(|issue| {
        issue.field == InvoiceField::LineItemVatAmount && issue.kind == ValidationKind::Mismatch
    }));
}
