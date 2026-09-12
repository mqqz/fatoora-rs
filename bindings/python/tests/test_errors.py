import pytest

from fatoora import InvoiceBuilder, InvoiceSubType, InvoiceTypeKind
from fatoora.errors import FfiError, FfiErrorKind, ValidationError, error_class_for_code


def test_validation_issues_cross_the_ffi_boundary():
    builder = InvoiceBuilder.new(InvoiceTypeKind.TAX, InvoiceSubType.SIMPLIFIED)
    with pytest.raises(ValidationError) as caught:
        builder.build()
    error = caught.value
    assert error.code == 2
    assert error.kind == FfiErrorKind.VALIDATION
    assert error.details["type"] == "invoice_validation"
    assert any(issue["field"] == "seller" for issue in error.details["issues"])
    assert all("kind" in issue for issue in error.details["issues"])


def test_unknown_codes_and_details_remain_available():
    details = {"type": "future_error", "new_field": ["some value"]}
    error = error_class_for_code(999)("future message", 999, details)
    assert type(error) is FfiError
    assert error.code == 999
    assert error.kind is None
    assert error.details == details
    assert str(error) == "future message"


def test_bundled_declarations_use_opaque_errors(monkeypatch):
    import json
    import fatoora._lib as module

    monkeypatch.setattr(module, "_find_header", lambda: None)
    bindings = module.FfiLibrary()
    ffi, lib = bindings.ffi, bindings.lib
    with pytest.raises(ValueError):
        ffi.sizeof("FfiError")
    result = lib.fatoora_csr_properties_from_str(b"csr.common.name=example")
    assert not result.ok
    try:
        assert lib.fatoora_error_code(result.error) == 1
        value = lib.fatoora_error_details_json(result.error)
        try:
            details = json.loads(ffi.string(value.ptr).decode("utf-8"))
        finally:
            lib.fatoora_string_free(value)
        assert details["type"] == "missing_property"
        assert details["key"]
    finally:
        lib.fatoora_error_free(result.error)


def test_invalid_key_uses_shared_input_classification():
    from fatoora.api import SigningKey
    from fatoora.errors import InvalidInputError

    with pytest.raises(InvalidInputError) as caught:
        SigningKey.from_pem("invalid key")
    assert caught.value.details["type"] == "key_decode"


def test_decimal_error_keeps_its_details():
    from fatoora import VatCategory
    from fatoora.errors import InvalidInputError

    builder = InvoiceBuilder.new(InvoiceTypeKind.TAX, InvoiceSubType.SIMPLIFIED)
    with pytest.raises(InvalidInputError) as caught:
        builder.add_line_item("item", "not-a-number", "PCE", "1", "15", VatCategory.STANDARD)
    assert caught.value.details["type"] == "invalid_decimal"


def test_imported_invoice_validation_keeps_structured_issues():
    from pathlib import Path
    import re
    from fatoora import parse_finalized_invoice_xml

    fixture = Path(__file__).resolve().parents[3] / "fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml"
    xml = re.sub(r"(<cbc:Percent>)[^<]*(</cbc:Percent>)", r"\g<1>-1\g<2>", fixture.read_text())
    with pytest.raises(ValidationError) as caught:
        parse_finalized_invoice_xml(xml)
    assert caught.value.details["type"] == "invoice_validation"
    assert caught.value.details["issues"][0]["field"] == "line_item_vat_rate"
    assert caught.value.details["issues"][0]["kind"] == "out_of_range"
    assert caught.value.details["issues"][0]["line_item_index"] == 0


@pytest.mark.parametrize("use_header", [False, True])
def test_native_integer_widths_and_error_handle_layout(monkeypatch, use_header):
    import ctypes
    from cffi import FFI
    import fatoora._lib as module

    if not use_header:
        monkeypatch.setattr(module, "_find_header", lambda: None)
    else:
        assert module._find_header() is not None
    bindings = module.FfiLibrary()
    ffi = bindings.ffi
    native = FFI()
    for name, expected_size in [("size_t", ctypes.sizeof(ctypes.c_size_t)),
                                ("uintptr_t", ctypes.sizeof(ctypes.c_void_p)),
                                ("int32_t", 4)]:
        assert ffi.sizeof(name) == expected_size
        # Compare against CFFI's native typedef, not a platform-specific alias.
        assert ffi.typeof(name) == native.typeof(name)
    with pytest.raises(ValueError):
        ffi.sizeof("FfiError")
