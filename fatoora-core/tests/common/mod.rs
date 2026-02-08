use base64ct::{Base64, Encoding};
use fatoora_core::invoice::{
    Address, FinalizedInvoice, InvoiceBuilder, InvoiceFlags, InvoiceNote, InvoiceSubType,
    InvoiceType, LineItem, OriginalInvoiceRef, OtherId, Party, SellerRole, VatCategory,
};
use fatoora_core::csr::SigningKey;

#[allow(dead_code)]
pub fn dummy_finalized_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Inc".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified));
    builder
        .set_id("INV-1")
        .set_uuid("8e6000cf-1a98-4174-b3e7-b5d5954bc10d")
        .set_issue_datetime("2024-01-01T12:30:00Z")
        .set_currency("SAR")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(0)
        .set_seller(seller)
        .set_payment_means_code("10")
        .set_vat_category(VatCategory::Standard);
    for item in dummy_line_items() {
        builder.add_line_item(item);
    }
    builder.build().expect("build dummy invoice")
}

#[allow(dead_code)]
pub fn complex_standard_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Global Trading Co".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let buyer = Party::<fatoora_core::invoice::BuyerRole>::new(
        "Blue Desert Retail LLC".into(),
        dummy_buyer_address(),
        Some("310122393500003".into()),
        None,
    )
    .expect("valid buyer");

    let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Standard));
    builder
        .set_id("INV-STD-1001")
        .set_uuid("b2a43c49-3aab-4e3b-9d67-0da45a5e33cc")
        .set_issue_datetime("2024-02-10T09:15:00Z")
        .set_currency("SAR")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(7)
        .set_seller(seller)
        .set_buyer(buyer)
        .set_payment_means_code("30")
        .set_vat_category(VatCategory::Standard)
        .set_note(InvoiceNote::new("en", "Complex standard invoice"))
        .invoice_level_charge(12.5)
        .invoice_level_discount(20.0)
        .allowance_reason("Seasonal discount")
        .flags(InvoiceFlags::EXPORT | InvoiceFlags::SELF_BILLED);

    builder
        .add_line_item(LineItem::new(
            "Consulting Services",
            2.0,
            "HUR",
            150.0,
            15.0,
            VatCategory::Standard,
        ))
        .add_line_item(LineItem::new(
            "Software License",
            1.0,
            "EA",
            500.0,
            15.0,
            VatCategory::Standard,
        ))
        .add_line_item(LineItem::new(
            "Export Item",
            3.0,
            "EA",
            200.0,
            0.0,
            VatCategory::Zero,
        ));

    builder.build().expect("build complex standard invoice")
}

#[allow(dead_code)]
pub fn credit_note_standard_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Global Trading Co".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let buyer = Party::<fatoora_core::invoice::BuyerRole>::new(
        "Blue Desert Retail LLC".into(),
        dummy_buyer_address(),
        Some("310122393500003".into()),
        None,
    )
    .expect("valid buyer");

    let original = OriginalInvoiceRef::new("INV-ORIG-900")
        .with_uuid("0e16f6d7-1c7d-4e7f-9c52-5f1f0f7ef7b4")
        .with_issue_date_str("2024-01-15")
        .expect("valid original invoice ref");

    let mut builder = InvoiceBuilder::new(InvoiceType::CreditNote(
        InvoiceSubType::Standard,
        original,
        "Return of goods".into(),
    ));

    builder
        .set_id("CRN-1001")
        .set_uuid("9d3f5cf1-6808-4e22-9bf6-1c9c2b9b0dc9")
        .set_issue_datetime("2024-02-12T10:00:00Z")
        .set_currency("SAR")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(8)
        .set_seller(seller)
        .set_buyer(buyer)
        .set_payment_means_code("10")
        .set_vat_category(VatCategory::Standard)
        .set_note(InvoiceNote::new("en", "Credit note for returned items"))
        .invoice_level_discount(15.0)
        .allowance_reason("Return allowance");

    builder.add_line_item(LineItem::new(
        "Returned Item A",
        1.0,
        "EA",
        250.0,
        15.0,
        VatCategory::Standard,
    ));

    builder.build().expect("build credit note")
}

#[allow(dead_code)]
pub fn debit_note_standard_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Global Trading Co".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let buyer = Party::<fatoora_core::invoice::BuyerRole>::new(
        "Blue Desert Retail LLC".into(),
        dummy_buyer_address(),
        Some("310122393500003".into()),
        None,
    )
    .expect("valid buyer");

    let original = OriginalInvoiceRef::new("INV-ORIG-901")
        .with_uuid("7c580b8a-ef52-4d99-9c53-9ac2e5b9d6a9")
        .with_issue_date_str("2024-01-20")
        .expect("valid original invoice ref");

    let mut builder = InvoiceBuilder::new(InvoiceType::DebitNote(
        InvoiceSubType::Standard,
        original,
        "Additional service charge".into(),
    ));

    builder
        .set_id("DBN-1001")
        .set_uuid("2c6d3503-9f1a-4d4f-8a7d-6d0bb5c6f6d5")
        .set_issue_datetime("2024-02-15T14:20:00Z")
        .set_currency("SAR")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(9)
        .set_seller(seller)
        .set_buyer(buyer)
        .set_payment_means_code("30")
        .set_vat_category(VatCategory::Standard)
        .set_note(InvoiceNote::new("en", "Debit note for extra charges"))
        .invoice_level_charge(30.0)
        .allowance_reason("Additional service charge");

    builder.add_line_item(LineItem::new(
        "Additional Service",
        1.0,
        "EA",
        300.0,
        15.0,
        VatCategory::Standard,
    ));

    builder.build().expect("build debit note")
}

#[allow(dead_code)]
pub fn prepayment_standard_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Global Trading Co".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let buyer = Party::<fatoora_core::invoice::BuyerRole>::new(
        "Blue Desert Retail LLC".into(),
        dummy_buyer_address(),
        Some("310122393500003".into()),
        None,
    )
    .expect("valid buyer");

    let mut builder = InvoiceBuilder::new(InvoiceType::Prepayment(InvoiceSubType::Standard));
    builder
        .set_id("PP-1001")
        .set_uuid("7d25c3a8-1c7a-4a1e-9b25-2d4e1a8b4c10")
        .set_issue_datetime("2024-02-18T08:05:00Z")
        .set_currency("SAR")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(10)
        .set_seller(seller)
        .set_buyer(buyer)
        .set_payment_means_code("30")
        .set_vat_category(VatCategory::Standard)
        .set_note(InvoiceNote::new("en", "Prepayment invoice"))
        .invoice_level_charge(5.0)
        .flags(InvoiceFlags::THIRD_PARTY | InvoiceFlags::SUMMARY);

    builder
        .add_line_item(LineItem::new(
            "Prepayment Service A",
            1.0,
            "EA",
            250.0,
            15.0,
            VatCategory::Standard,
        ))
        .add_line_item(LineItem::new(
            "Prepayment Service B",
            2.0,
            "EA",
            120.0,
            15.0,
            VatCategory::Standard,
        ));

    builder.build().expect("build prepayment invoice")
}

#[allow(dead_code)]
pub fn mixed_vat_simplified_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Inc".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified));
    builder
        .set_id("INV-SIMP-2001")
        .set_uuid("5c8e7f12-1f2a-4d4a-9a5b-5f6e7d8c9b10")
        .set_issue_datetime("2024-02-20T11:45:00Z")
        .set_currency("SAR")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(11)
        .set_seller(seller)
        .set_payment_means_code("10")
        .set_vat_category(VatCategory::Standard)
        .set_note(InvoiceNote::new("en", "Mixed VAT simplified invoice"))
        .invoice_level_discount(5.0)
        .allowance_reason("Promo")
        .flags(InvoiceFlags::NOMINAL | InvoiceFlags::SUMMARY);

    builder
        .add_line_item(LineItem::new(
            "Standard Rated Item",
            2.0,
            "EA",
            80.0,
            15.0,
            VatCategory::Standard,
        ))
        .add_line_item(LineItem::new(
            "Zero Rated Item",
            1.0,
            "EA",
            200.0,
            0.0,
            VatCategory::Zero,
        ))
        .add_line_item(LineItem::new(
            "Exempt Item",
            1.0,
            "EA",
            150.0,
            0.0,
            VatCategory::Exempt,
        ));

    builder.build().expect("build mixed vat simplified invoice")
}

#[allow(dead_code)]
pub fn export_self_billed_standard_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Exporters Ltd".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let buyer = Party::<fatoora_core::invoice::BuyerRole>::new(
        "Global Importers Inc".into(),
        dummy_buyer_address(),
        Some("310122393500003".into()),
        None,
    )
    .expect("valid buyer");

    let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Standard));
    builder
        .set_id("INV-EXP-3001")
        .set_uuid("8f1e4f20-9e40-4a2c-8c7f-65d7b9c3c9a1")
        .set_issue_datetime("2024-02-22T13:10:00Z")
        .set_currency("SAR")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(12)
        .set_seller(seller)
        .set_buyer(buyer)
        .set_payment_means_code("30")
        .set_vat_category(VatCategory::Zero)
        .set_note(InvoiceNote::new("en", "Export self-billed invoice"))
        .flags(InvoiceFlags::EXPORT | InvoiceFlags::SELF_BILLED);

    builder.add_line_item(LineItem::new(
        "Exported Goods",
        5.0,
        "EA",
        120.0,
        0.0,
        VatCategory::Zero,
    ));

    builder.build().expect("build export self-billed invoice")
}

#[allow(dead_code)]
pub fn out_of_scope_standard_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Services Co".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let buyer = Party::<fatoora_core::invoice::BuyerRole>::new(
        "Domestic Customer".into(),
        dummy_buyer_address(),
        Some("310122393500003".into()),
        None,
    )
    .expect("valid buyer");

    let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Standard));
    builder
        .set_id("INV-OOS-4001")
        .set_uuid("1c7d7c2b-9a0c-4fdd-9f4b-7c6d41b9f0a2")
        .set_issue_datetime("2024-02-24T16:30:00Z")
        .set_currency("SAR")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(13)
        .set_seller(seller)
        .set_buyer(buyer)
        .set_payment_means_code("30")
        .set_vat_category(VatCategory::OutOfScope)
        .set_note(InvoiceNote::new("en", "Out of scope invoice"))
        .flags(InvoiceFlags::SUMMARY);

    builder.add_line_item(LineItem::new(
        "Out of Scope Service",
        1.0,
        "EA",
        400.0,
        0.0,
        VatCategory::OutOfScope,
    ));

    builder.build().expect("build out of scope invoice")
}

#[allow(dead_code)]
pub fn simplified_credit_note_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Inc".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let original = OriginalInvoiceRef::new("INV-ORIG-990")
        .with_uuid("3f1a7b5e-77d1-4f2b-8b74-508f2f4db211")
        .with_issue_date_str("2024-01-05")
        .expect("valid original invoice ref");

    let mut builder = InvoiceBuilder::new(InvoiceType::CreditNote(
        InvoiceSubType::Simplified,
        original,
        "Price adjustment".into(),
    ));

    builder
        .set_id("CRN-SIMP-5001")
        .set_uuid("9b1f5f7c-5d30-4f2b-9e6d-7b2a0f5b7f11")
        .set_issue_datetime("2024-02-26T09:45:00Z")
        .set_currency("SAR")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(14)
        .set_seller(seller)
        .set_payment_means_code("10")
        .set_vat_category(VatCategory::Standard)
        .set_note(InvoiceNote::new("en", "Simplified credit note"))
        .invoice_level_discount(10.0)
        .allowance_reason("Price adjustment");

    builder.add_line_item(LineItem::new(
        "Adjusted Item",
        1.0,
        "EA",
        100.0,
        15.0,
        VatCategory::Standard,
    ));

    builder.build().expect("build simplified credit note")
}

#[allow(dead_code)]
pub fn simplified_debit_note_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Inc".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let original = OriginalInvoiceRef::new("INV-ORIG-991")
        .with_uuid("4d7c9a55-7a5e-4e58-8cb1-9e1f6b0f2d3c")
        .with_issue_date_str("2024-01-07")
        .expect("valid original invoice ref");

    let mut builder = InvoiceBuilder::new(InvoiceType::DebitNote(
        InvoiceSubType::Simplified,
        original,
        "Additional charge".into(),
    ));

    builder
        .set_id("DBN-SIMP-5002")
        .set_uuid("0b1f2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d")
        .set_issue_datetime("2024-02-27T15:20:00Z")
        .set_currency("SAR")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(15)
        .set_seller(seller)
        .set_payment_means_code("10")
        .set_vat_category(VatCategory::Standard)
        .set_note(InvoiceNote::new("en", "Simplified debit note"))
        .invoice_level_charge(8.0)
        .allowance_reason("Additional charge");

    builder.add_line_item(LineItem::new(
        "Extra Service",
        1.0,
        "EA",
        80.0,
        15.0,
        VatCategory::Standard,
    ));

    builder.build().expect("build simplified debit note")
}

#[allow(dead_code)]
pub fn foreign_currency_standard_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Global Trading Co".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let buyer = Party::<fatoora_core::invoice::BuyerRole>::new(
        "International Buyer".into(),
        dummy_buyer_address(),
        Some("310122393500003".into()),
        None,
    )
    .expect("valid buyer");

    let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Standard));
    builder
        .set_id("INV-FX-6001")
        .set_uuid("2f3b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d")
        .set_issue_datetime("2024-02-28T12:00:00Z")
        .set_currency("USD")
        .set_previous_invoice_hash(
            "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
        )
        .set_invoice_counter(16)
        .set_seller(seller)
        .set_buyer(buyer)
        .set_payment_means_code("30")
        .set_vat_category(VatCategory::Standard)
        .set_note(InvoiceNote::new("en", "Foreign currency invoice"));

    builder.add_line_item(LineItem::new(
        "International Service",
        1.0,
        "EA",
        300.0,
        15.0,
        VatCategory::Standard,
    ));

    builder.build().expect("build foreign currency invoice")
}

#[allow(dead_code)]
pub fn signer_from_csid(
    binary_security_token: &str,
    key: &SigningKey,
) -> fatoora_core::invoice::sign::InvoiceSigner {
    // The token is base64-encoded DER bytes, which themselves are base64-encoded.
    let b64_der_bytes = Base64::decode_vec(binary_security_token).expect("decode token");
    let b64_der = String::from_utf8(b64_der_bytes).expect("token utf-8");
    let der = Base64::decode_vec(&b64_der).expect("decode DER");
    let key_der = key.to_der().expect("key der");
    fatoora_core::invoice::sign::InvoiceSigner::from_der(&der, &key_der)
        .expect("signer")
}

#[allow(dead_code)]
fn dummy_seller_address() -> Address {
    Address {
        country_code: fatoora_core::invoice::CountryCode::parse("SAU").expect("country code"),
        city: "Riyadh".into(),
        street: "King Fahd".into(),
        additional_street: None,
        building_number: "1234".into(),
        additional_number: Some("5678".into()),
        postal_code: "12222".into(),
        subdivision: None,
        district: Some("Olaya".into()),
    }
}

#[allow(dead_code)]
fn dummy_buyer_address() -> Address {
    Address {
        country_code: fatoora_core::invoice::CountryCode::parse("SAU").expect("country code"),
        city: "Jeddah".into(),
        street: "King Abdulaziz".into(),
        additional_street: Some("Al Zahra".into()),
        building_number: "4321".into(),
        additional_number: None,
        postal_code: "21577".into(),
        subdivision: Some("Al Zahra".into()),
        district: Some("North".into()),
    }
}

#[allow(dead_code)]
fn dummy_line_items() -> Vec<LineItem> {
    vec![LineItem::new(
        "Item",
        1.0,
        "PCE",
        100.0,
        15.0,
        VatCategory::Standard,
    )]
}
