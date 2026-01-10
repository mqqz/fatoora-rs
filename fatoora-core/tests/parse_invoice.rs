use chrono::TimeZone;
use fatoora_core::invoice::xml::ToXml;
use fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml_file;
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml_file;
use fatoora_core::invoice::{
    Address, InvoiceBuilder, InvoiceSubType, InvoiceType, LineItem, OriginalInvoiceRef, Party,
    SellerRole, VatCategory,
};
use iso_currency::Currency;
use isocountry::CountryCode;
use std::path::Path;

#[test]
fn parse_sample_simplified_invoice() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
    let invoice = parse_finalized_invoice_xml_file(&path).expect("parse invoice");
    let data = invoice.data();

    assert_eq!(data.id, "SME00010");
    assert_eq!(data.uuid, "8e6000cf-1a98-4174-b3e7-b5d5954bc10d");
    assert_eq!(data.issue_datetime.date_naive().to_string(), "2022-08-17");
    assert_eq!(
        data.issue_datetime.time().format("%H:%M:%S").to_string(),
        "17:41:08"
    );
    assert_eq!(data.currency.code(), "SAR");
    assert_eq!(
        data.previous_invoice_hash,
        "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ=="
    );
    assert_eq!(data.invoice_counter.as_deref(), Some("10"));

    assert_eq!(
        data.seller.name(),
        "شركة توريد التكنولوجيا بأقصى سرعة المحدودة | Maximum Speed Tech Supply LTD"
    );
    assert_eq!(data.seller.vat_id().unwrap().as_str(), "399999999900003");
    assert_eq!(data.seller.other_id().unwrap().as_str(), "1010010000");
    assert_eq!(data.seller.other_id().unwrap().scheme_id(), Some("CRN"));

    let address = data.seller.address();
    assert!(address.street.contains("Prince Sultan"));
    assert_eq!(address.building_number, "2322");
    assert!(address.city.contains("Riyadh"));
    assert_eq!(address.postal_code, "23333");
    assert_eq!(address.country_code.alpha2(), "SA");

    let totals = invoice.totals();
    assert_eq!(totals.line_extension(), 201.0);
    assert_eq!(totals.tax_amount(), 30.15);
    assert_eq!(totals.tax_inclusive_amount(), 231.15);

    assert_eq!(data.line_items.len(), 2);
    assert_eq!(data.line_items[0].description, "كتاب");
    assert_eq!(data.line_items[0].quantity, 33.0);
    assert_eq!(data.line_items[0].unit_code, "PCE");
    assert_eq!(data.line_items[0].total_amount, 99.0);
    assert_eq!(data.line_items[0].unit_price, 3.0);
    assert_eq!(data.line_items[0].vat_rate, 15.0);
    assert_eq!(data.line_items[0].vat_amount, 14.85);
    assert!(matches!(
        data.line_items[0].vat_category,
        fatoora_core::invoice::VatCategory::Standard
    ));
    assert_eq!(data.line_items[1].description, "قلم");
    assert_eq!(data.line_items[1].quantity, 3.0);
    assert_eq!(data.line_items[1].unit_code, "PCE");
    assert_eq!(data.line_items[1].total_amount, 102.0);
    assert_eq!(data.line_items[1].unit_price, 34.0);
    assert_eq!(data.line_items[1].vat_rate, 15.0);
    assert_eq!(data.line_items[1].vat_amount, 15.30);
    assert!(matches!(
        data.line_items[1].vat_category,
        fatoora_core::invoice::VatCategory::Standard
    ));
}

#[test]
fn parse_signed_invoice_from_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/invoices/sample-simplified-invoice.xml");
    let xml = std::fs::read_to_string(&path).expect("read xml");
    let signed = parse_signed_invoice_xml_file(&path).expect("parse signed invoice");
    let data = signed.data();

    assert_eq!(data.id, "SME00010");
    assert!(signed.xml().contains("<ds:Signature"));
    assert!(!signed.qr_code().trim().is_empty());
    assert_eq!(
        signed.invoice_hash(),
        "z5F9qsS6oWyDhehD8u8S0DaxV+2CUiUz9Y+UsR61JgQ="
    );
    assert!(signed.zatca_key_signature().is_some());

    let props = signed.signed_properties();
    assert_eq!(
        props
            .signing_time()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "2025-07-22T15:51:28Z"
    );
    assert_eq!(
        props.cert_hash(),
        "ZDMwMmI0MTE1NzVjOTU2NTk4YzVlODhhYmI0ODU2NDUyNTU2YTVhYjhhMDFmN2FjYjk1YTA2OWQ0NjY2MjQ4NQ=="
    );
    assert_eq!(
        props.issuer(),
        "CN=PRZEINVOICESCA4-CA, DC=extgazt, DC=gov, DC=local"
    );
    assert_eq!(
        props.serial(),
        "379112742831380471835263969587287663520528387"
    );
    assert_eq!(
        props.signed_props_hash(),
        "ZmMwY2ZhNDljNzNjZDA5NmY4NDM4MmY1ZmY1YTA0NjY3MzY4NzMxOGJhYmZmNWU1OGYzZWJlODI3ZDgyZGVkZA=="
    );

    let serialized = signed.to_xml().expect("serialize signed invoice");
    assert_eq!(serialized.trim(), xml.trim());
}

#[test]
fn credit_note_serializes_billing_reference_and_reason() {
    let seller = Party::<SellerRole>::new(
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
            district: None,
        },
        "301121971500003",
        None,
    )
    .expect("valid seller");

    let line_item = LineItem {
        description: "Item".into(),
        quantity: 1.0,
        unit_code: "PCE".into(),
        unit_price: 100.0,
        total_amount: 100.0,
        vat_rate: 15.0,
        vat_amount: 15.0,
        vat_category: VatCategory::Standard,
    };

    let issue_datetime = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
        .unwrap()
        .and_hms_opt(12, 30, 0)
        .unwrap();

    let original = OriginalInvoiceRef::new("INV-ORIG")
        .with_uuid("uuid-orig")
        .with_issue_date(chrono::NaiveDate::from_ymd_opt(2023, 12, 31).unwrap());

    let invoice = InvoiceBuilder::new(
        InvoiceType::CreditNote(
            InvoiceSubType::Standard,
            original,
            "pricing correction".into(),
        ),
        "CR-1",
        "uuid-cr-1",
        chrono::Utc.from_utc_datetime(&issue_datetime),
        Currency::SAR,
        "hash",
        seller,
        vec![line_item],
        "10",
        VatCategory::Standard,
    )
    .build()
    .expect("build credit note");

    let xml = invoice.to_xml().expect("serialize credit note");
    assert!(xml.contains("<cac:BillingReference>"));
    assert!(xml.contains("<cbc:ID>INV-ORIG</cbc:ID>"));
    assert!(xml.contains("<cbc:UUID>uuid-orig</cbc:UUID>"));
    assert!(xml.contains("<cbc:IssueDate>2023-12-31</cbc:IssueDate>"));
    assert!(xml.contains("<cbc:InstructionNote>pricing correction</cbc:InstructionNote>"));
}
