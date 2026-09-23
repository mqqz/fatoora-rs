from pathlib import Path

import pytest

from fatoora import parse_signed_invoice_xml
from fatoora.errors import FfiError


def test_signed_xml_copy_and_consuming_access():
    path = Path(__file__).resolve().parents[3] / "fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml"
    xml = path.read_text()
    signed = parse_signed_invoice_xml(xml)
    copied = signed.xml()
    assert copied == xml
    assert signed.into_xml() == xml
    assert copied == xml
    with pytest.raises(FfiError):
        signed.xml()
    with pytest.raises(FfiError):
        signed.into_xml()
    signed.close()


def test_generated_signed_invoice_consumption_keeps_copy_and_owned_data():
    from fatoora import _native

    path = Path(__file__).resolve().parents[3] / "fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml"
    xml = path.read_text()
    signed = _native.SignedInvoice.from_xml(xml)
    copied = signed.xml()
    data = signed.data()
    invoice_id = data.id()
    assert signed.into_xml() == xml
    assert copied == xml
    assert data.id() == invoice_id
    for method in (signed.xml, signed.into_xml, signed.data):
        with pytest.raises(Exception) as caught:
            method()
        error = caught.value.args[0]
        assert isinstance(error, _native.BindingError)
        assert error.code() == 1
    del signed
    assert data.id() == invoice_id


def test_closed_facade_is_idempotent_and_rejects_use():
    path = Path(__file__).resolve().parents[3] / "fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml"
    signed = parse_signed_invoice_xml(path.read_text())
    signed.close()
    signed.close()
    with pytest.raises(FfiError) as caught:
        signed.into_xml()
    assert caught.value.code == 1
