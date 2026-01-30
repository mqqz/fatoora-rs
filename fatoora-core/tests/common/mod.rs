use base64ct::{Base64, Encoding};
use fatoora_core::invoice::{
    Address, FinalizedInvoice, InvoiceBuilder, InvoiceSubType, InvoiceType, LineItem, OtherId,
    Party, SellerRole, VatCategory,
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
