use fatoora_core::invoice::{
    InvoiceBuilder, InvoiceError, InvoiceField, InvoiceSubType, InvoiceType, LineItem,
    RequiredInvoiceFields, ValidationKind, VatCategory,
};
use fatoora_core::invoice::{OtherId, Party, SellerRole};
use iso_currency::Currency;
use isocountry::CountryCode;

fn dummy_seller() -> Party<SellerRole> {
    Party::<SellerRole>::new(
        "Acme Inc".into(),
        fatoora_core::invoice::Address::new(
            CountryCode::SAU,
            "Riyadh",
            "King Fahd",
            None,
            "1234",
            Some("5678".into()),
            "12222",
            None,
            Some("Olaya".into()),
        ),
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
    let line_item = LineItem::new(
        "",
        -1.0,
        "",
        -1.0,
        -1.0,
        -1.0,
        -1.0,
        VatCategory::Standard,
    );
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
    let mut has_vat_rate = false;
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
            (InvoiceField::LineItemVatRate, ValidationKind::OutOfRange) => {
                has_vat_rate = true;
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
    assert!(has_vat_rate);
    assert!(has_vat_amount);
}
