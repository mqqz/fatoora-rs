from decimal import Decimal

import pytest
from fatoora.errors import FfiError

from fatoora import InvoiceBuilder, InvoiceSubType, InvoiceTypeKind, VatCategory


def builder():
    b = InvoiceBuilder.new(InvoiceTypeKind.TAX, InvoiceSubType.SIMPLIFIED)
    b.set_id("numeric")
    b.set_uuid("numeric-uuid")
    b.set_issue_datetime("2024-01-01T12:30:00Z")
    b.set_currency("SAR")
    b.set_previous_invoice_hash("hash")
    b.set_invoice_counter(1)
    b.set_payment_means_code("10")
    b.set_vat_category(VatCategory.STANDARD)
    b.set_seller(name="Acme", country_code="SA", city="Riyadh", street="King Fahd",
                 building_number="1234", postal_code="12222", vat_id="399999999900003")
    return b


def test_decimal_strings_round_trip_through_c_abi():
    b = builder()
    for _ in range(3):
        b.add_line_item("item", Decimal("1"), "PCE", "0.03", 15, VatCategory.STANDARD)
    invoice = b.build()
    totals = invoice.totals()
    assert isinstance(totals.tax_amount, Decimal)
    assert totals.tax_amount == Decimal("0.01")
    assert totals.tax_inclusive == Decimal("0.10")
    assert invoice.line_item(0).unit_price == Decimal("0.03")
    assert invoice.line_item(0).vat_amount == Decimal("0.00")
    assert ">0.10</cbc:TaxInclusiveAmount>" in invoice.xml()


def test_float_input_is_rejected():
    b = builder()
    with pytest.raises(TypeError, match="Decimal, str, or int"):
        b.add_line_item("item", 1, "PCE", 0.03, 15, VatCategory.STANDARD)


@pytest.mark.parametrize("bad", ["NaN", "1e2", "0.00000000000000000000000000001"])
def test_invalid_decimal_reaches_binding_error(bad):
    b = builder()
    with pytest.raises(FfiError) as error:
        b.add_line_item("item", 1, "PCE", bad, 15, VatCategory.STANDARD)
    assert "unit_price" in str(error.value)


def test_import_preserves_signed_payable_adjustment():
    from pathlib import Path
    from fatoora import parse_finalized_invoice_xml

    path = Path(__file__).resolve().parents[3] / "fatoora-core/tests/fixtures/invoices/Standard/Invoice/Standard Invoice with Payable Rounding Adjustment.xml"
    invoice = parse_finalized_invoice_xml(path.read_text())
    totals = invoice.totals()
    assert totals.payable_rounding_amount == Decimal("-0.01")
    assert totals.prepaid_amount == Decimal("0")
    assert totals.payable_amount == Decimal("1000")
    assert invoice.line_item(0).vat_amount == Decimal("130.43")
    assert totals.tax_amount == Decimal("130.44")
