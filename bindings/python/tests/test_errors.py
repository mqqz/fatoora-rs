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



def test_generated_error_is_owned_and_preserves_missing_property():
    import gc
    from fatoora import CsrProperties
    from fatoora.errors import InvalidInputError
    with pytest.raises(InvalidInputError) as caught:
        CsrProperties.from_properties_str("csr.common.name=example")
    details = caught.value.details
    del caught
    gc.collect()
    assert details["type"] == "missing_property"
    assert details["key"]
