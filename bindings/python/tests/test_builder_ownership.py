import pytest

from fatoora.errors import FfiError
from test_numeric_contract import builder


def test_failed_setter_can_be_corrected_and_build_consumes():
    from fatoora import VatCategory

    b = builder()
    with pytest.raises(FfiError):
        b.set_currency("invalid")
    b.set_currency("SAR")
    b.add_line_item("item", 1, "PCE", 100, 15, VatCategory.STANDARD)
    invoice = b.build()
    assert invoice.id() == "numeric"
    with pytest.raises(FfiError):
        b.set_id("after build")
    b.close()
    invoice.close()
