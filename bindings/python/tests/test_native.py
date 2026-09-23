"""Run against the installed wheel, without a source-tree PYTHONPATH."""
from decimal import Decimal
import gc
import xml.etree.ElementTree as ET

import pytest

from fatoora.errors import FfiError, InvalidInputError
from fatoora import InvoiceBuilder, InvoiceTypeKind, InvoiceSubType, VatCategory


def builder():
    b = InvoiceBuilder.new(InvoiceTypeKind.TAX, InvoiceSubType.SIMPLIFIED)
    b.set_id("INV-1")
    b.set_uuid("8e6000cf-1a98-4174-b3e7-b5d5954bc10d")
    b.set_issue_datetime("2024-01-01T12:30:00Z")
    b.set_previous_invoice_hash("hash")
    b.set_invoice_counter(1)
    b.set_currency("SAR")
    b.set_payment_means_code("10")
    b.set_vat_category(VatCategory.STANDARD)
    b.set_seller(name="شركة الاختبار", vat_id="399999999900003", other_id="7003339333", other_id_scheme="CRN",
                 country_code="SA", city="Riyadh", street="King Fahd", building_number="1234", postal_code="12222", district="Olaya")
    return b


def line(b, price="0.3333", quantity=3):
    b.add_line_item(description="خدمة", unit_code="PCE", unit_price=price, quantity=quantity, vat_rate=15, vat_category=VatCategory.STANDARD)
    return b


def test_exact_decimal_xml_and_owned_output():
    b = builder()
    invoice = line(b, Decimal("0.3333")).build()
    xml = invoice.to_xml()
    del invoice
    gc.collect()
    root = ET.fromstring(xml)
    ns = {"cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"}
    assert root.find(".//cbc:PriceAmount", ns).text == "0.3333"
    assert root.find(".//cbc:TaxInclusiveAmount", ns).text == "1.15"
    assert "شركة الاختبار" in xml
    with pytest.raises(InvalidInputError, match="consumed"):
        b.build()
    with pytest.raises(InvalidInputError, match="consumed"):
        line(b)


def test_error_details_survive_collection_and_input_failure_is_recoverable():
    b = builder()
    with pytest.raises(InvalidInputError) as captured:
        line(b, "invalid")
    error = captured.value
    assert error.code == 1
    assert error.kind.name == "INVALID_INPUT"
    assert error.details["type"] == "invalid_decimal"
    assert line(b, "1.005", 1).build().to_xml().find(">1.01</cbc:LineExtensionAmount>") >= 0
    del captured, b
    gc.collect()
    assert error.details["type"] == "invalid_decimal"
    assert str(error)


def test_failed_build_consumes():
    b = builder()
    with pytest.raises(FfiError):
        b.build()
    with pytest.raises(InvalidInputError, match="consumed"):
        b.build()


def test_embedded_nul_is_rejected_without_consumption():
    b = builder()
    with pytest.raises(InvalidInputError, match="NUL"):
        b.add_line_item(description="bad\0text", unit_code="PCE", unit_price=1, quantity=1, vat_rate=15, vat_category=VatCategory.STANDARD)
    assert line(b).build().to_xml()
    with pytest.raises(InvalidInputError, match="consumed"):
        b.build()


@pytest.mark.parametrize("value", [0.3333, True, None])
def test_float_bool_and_none_are_rejected(value):
    b = builder()
    with pytest.raises(TypeError, match="decimal values"):
        line(b, value)
    assert line(b).build().to_xml()


@pytest.mark.parametrize("count", [1, 64])
def test_line_items_uses_one_snapshot_and_preserves_values(monkeypatch, count):
    b = builder()
    for index in range(count):
        b.add_line_item(description=f"Item {index}", quantity=1, unit_code="PCE",
                        unit_price=str(index + 1), vat_rate=15,
                        vat_category=VatCategory.STANDARD)
    invoice = b.build()
    expected = [invoice.line_item(i) for i in range(count)]
    invoke = invoice._invoke
    snapshots = 0

    def counted_invoke(name, *args):
        nonlocal snapshots
        if name == "data":
            snapshots += 1
        return invoke(name, *args)

    monkeypatch.setattr(invoice, "_invoke", counted_invoke)
    items = invoice.line_items()
    invoice.close()
    assert items == expected
    assert snapshots == 1, "collection must clone the invoice only once"
