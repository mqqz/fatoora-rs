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


def test_bundled_declarations_support_xml_ownership(monkeypatch):
    import fatoora._lib as module

    monkeypatch.setattr(module, "_find_header", lambda: None)
    bindings = module.FfiLibrary()
    ffi, lib = bindings.ffi, bindings.lib
    path = Path(__file__).resolve().parents[3] / "fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml"
    xml = path.read_bytes()
    parsed = lib.fatoora_parse_signed_invoice_xml(xml)
    assert parsed.ok
    handle = ffi.new("FfiSignedInvoice *", parsed.value)
    copied = lib.fatoora_signed_invoice_to_xml(handle)
    assert copied.ok and handle.ptr
    owned = lib.fatoora_signed_invoice_into_xml(handle)
    assert owned.ok and not handle.ptr
    try:
        assert ffi.string(copied.value.ptr) == xml
        assert ffi.string(owned.value.ptr) == xml
    finally:
        lib.fatoora_string_free(copied.value)
        lib.fatoora_string_free(owned.value)
        lib.fatoora_signed_invoice_free(handle)
