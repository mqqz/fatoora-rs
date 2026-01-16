use base64ct::{Base64, Encoding};
use chrono::TimeZone;
use fatoora_core::invoice::{
    Address, FinalizedInvoice, InvoiceBuilder, InvoiceSubType, InvoiceType, LineItem, OtherId,
    Party, RequiredInvoiceFields, SellerRole, VatCategory,
};
use iso_currency::Currency;
use isocountry::CountryCode;
use k256::ecdsa::SigningKey;
use k256::pkcs8::EncodePrivateKey;

#[allow(dead_code)]
pub fn dummy_finalized_invoice() -> FinalizedInvoice {
    let seller = Party::<SellerRole>::new(
        "Acme Inc".into(),
        dummy_seller_address(),
        "399999999900003",
        Some(OtherId::with_scheme("7003339333", "CRN")),
    )
    .expect("valid seller");

    let issue_datetime = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
        .unwrap()
        .and_hms_opt(12, 30, 0)
        .unwrap();

    let builder = InvoiceBuilder::new(RequiredInvoiceFields {
        invoice_type: InvoiceType::Tax(InvoiceSubType::Simplified),
        id: "INV-1".into(),
        uuid: "8e6000cf-1a98-4174-b3e7-b5d5954bc10d".into(),
        issue_datetime: chrono::Utc.from_utc_datetime(&issue_datetime),
        currency: Currency::SAR,
        previous_invoice_hash: "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==".into(),
        invoice_counter: 0,
        seller,
        line_items: dummy_line_items(),
        payment_means_code: "10".into(),
        vat_category: VatCategory::Standard,
    });
    builder
        .build()
    .expect("build dummy invoice")
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
    let key_der = key.to_pkcs8_der().expect("key der");
    fatoora_core::invoice::sign::InvoiceSigner::from_der(&der, key_der.as_bytes())
        .expect("signer")
}

#[allow(dead_code)]
fn dummy_seller_address() -> Address {
    Address::new(
        CountryCode::SAU,
        "Riyadh",
        "King Fahd",
        None,
        "1234",
        Some("5678".into()),
        "12222",
        None,
        Some("Olaya".into()),
    )
}

#[allow(dead_code)]
fn dummy_line_items() -> Vec<LineItem> {
    vec![LineItem::new(
        "Item",
        1.0,
        "PCE",
        100.0,
        100.0,
        15.0,
        15.0,
        VatCategory::Standard,
    )]
}
