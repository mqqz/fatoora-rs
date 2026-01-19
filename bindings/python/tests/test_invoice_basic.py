from __future__ import annotations

from datetime import datetime, timezone

from fatoora import InvoiceBuilder, InvoiceSubType, InvoiceTypeKind, VatCategory


def test_invoice_basic_xml() -> None:
    builder = InvoiceBuilder.new(
        invoice_type=InvoiceTypeKind.TAX,
        invoice_subtype=InvoiceSubType.SIMPLIFIED,
        invoice_id="INV-1",
        uuid="123e4567-e89b-12d3-a456-426614174000",
        issue_datetime=datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc),
        currency_code="SAR",
        previous_invoice_hash="hash",
        invoice_counter=1,
        payment_means_code="10",
        vat_category=VatCategory.STANDARD,
        seller_name="Acme Inc",
        seller_country_code="SAU",
        seller_city="Riyadh",
        seller_street="King Fahd",
        seller_building_number="1234",
        seller_postal_code="12222",
        seller_vat_id="399999999900003",
    )
    builder.add_line_item(
        description="Item",
        quantity=1.0,
        unit_code="PCE",
        unit_price=100.0,
        vat_rate=15.0,
        vat_category=VatCategory.STANDARD,
    )
    invoice = builder.build()
    xml = invoice.xml()
    assert "<Invoice" in xml
