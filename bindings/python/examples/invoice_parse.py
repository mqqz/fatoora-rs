from __future__ import annotations

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
    )
    builder.set_id("INV-42")
    builder.set_uuid("123e4567-e89b-12d3-a456-426614174000")
    builder.set_issue_datetime("2023-11-14T22:13:20Z")
    builder.set_currency("SAR")
    builder.set_previous_invoice_hash("hash")
    builder.set_invoice_counter(42)
    builder.set_payment_means_code("10")
    builder.set_vat_category(VatCategory.STANDARD)
    builder.set_seller(
        name="Acme Inc",
        country_code="SAU",
        city="Riyadh",
        street="King Fahd",
        building_number="1234",
        postal_code="12222",
        vat_id="399999999900003",
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
