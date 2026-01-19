from __future__ import annotations

from datetime import datetime, timezone

from fatoora import (
    InvoiceBuilder,
    InvoiceSubType,
    InvoiceTypeKind,
    VatCategory,
    parse_invoice_xml,
)


def main() -> None:
    builder = InvoiceBuilder.new(
        invoice_type=InvoiceTypeKind.TAX,
        invoice_subtype=InvoiceSubType.SIMPLIFIED,
        invoice_id="INV-42",
        uuid="123e4567-e89b-12d3-a456-426614174000",
        issue_datetime=datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc),
        currency_code="SAR",
        previous_invoice_hash="hash",
        invoice_counter=42,
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

    parsed = parse_invoice_xml(xml)
    print("items", parsed.line_item_count())
    print("totals", parsed.totals())


if __name__ == "__main__":
    main()
