from pathlib import Path

import pytest

from fatoora import (
    Config,
    Environment,
    InvalidInputError,
    ValidationError,
    XmlError,
    validate_xml_invoice_from_str,
    validate_zatca_invoice_from_str,
)

CORPUS = (
    Path(__file__).resolve().parents[3] / "fatoora-core/tests/fixtures/sdk-parity/cases"
)
SEED = "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ=="
OPTIONS = {"previous_invoice_hash": SEED, "evaluated_at": "2026-09-23T12:00:00+03:00"}


def test_valid_warning_and_rejected_reports_preserve_source_findings():
    with Config(Environment.NON_PRODUCTION) as config:
        for kind in ["standard", "simplified"]:
            xml = (CORPUS / f"{kind}-invoice/sdk-signed.xml").read_text()
            report = validate_zatca_invoice_from_str(config, xml, **OPTIONS)
            assert (
                report["is_valid"]
                and report["is_complete"]
                and not report["has_errors"]
            )
            assert len(report["stages"][1]["evaluated_assertions"]) == 105
            assert len(report["stages"][2]["evaluated_assertions"]) == 152
            assert any(
                f["severity"] == "warning" for f in report["stages"][2]["findings"]
            )
            assert validate_xml_invoice_from_str(config, xml)
        rejected = validate_zatca_invoice_from_str(config, "<wrong/>", **OPTIONS)
        assert rejected["has_errors"] and not rejected["is_valid"]
        assert rejected["stages"][0]["findings"][0]["code"] == "XSD_INVALID"
        assert all(s["status"] == "not_run" for s in rejected["stages"][1:])
    # Reports are owned values, surviving config release.
    assert report["profile"] == "zatca-sdk-238-R3.4.8"


def test_missing_context_and_chain_mismatch():
    xml = (CORPUS / "standard-invoice/input.xml").read_text()
    with Config(Environment.NON_PRODUCTION) as config:
        missing = validate_zatca_invoice_from_str(config, xml)
        assert not missing["is_valid"] and not missing["is_complete"]
        assert missing["stages"][5]["status"] == "context_required"
        wrong = validate_zatca_invoice_from_str(
            config, xml, previous_invoice_hash="A" * 43 + "="
        )
        assert wrong["is_complete"] and wrong["has_errors"]
        assert wrong["stages"][5]["findings"][0]["code"] == "PIH_MISMATCH"


def test_execution_failure_keeps_partial_report():
    xml = (CORPUS / "standard-invoice/input.xml").read_text()
    xml = xml.replace(
        '<cbc:LineExtensionAmount currencyID="SAR">300.00',
        '<cbc:LineExtensionAmount currencyID="[">300.00',
        1,
    )
    with (
        Config(Environment.NON_PRODUCTION) as config,
        pytest.raises(ValidationError) as caught,
    ):
        validate_zatca_invoice_from_str(config, xml, **OPTIONS)
    details = caught.value.details
    assert details["type"] == "zatca_validation_execution"
    assert details["assertion_site"] == "ksa:112:BR-KSA-CL-02"
    assert details["report"]["stages"][1]["status"] == "completed"
    assert details["report"]["stages"][2]["status"] == "evaluation_failed"
    assert not details["report"]["is_valid"]


def test_invalid_inputs_cannot_silently_truncate_or_succeed():
    with Config(Environment.NON_PRODUCTION) as config:
        for xml in ["<Invoice", "<Invoice>"]:
            with pytest.raises(XmlError) as caught:
                validate_zatca_invoice_from_str(config, xml, **OPTIONS)
            assert not caught.value.details["report"]["is_valid"]
        with pytest.raises(InvalidInputError):
            validate_zatca_invoice_from_str(config, "<!DOCTYPE x><x/>", **OPTIONS)
        with pytest.raises(InvalidInputError):
            validate_zatca_invoice_from_str(config, "<x/>", evaluated_at="bad")
        for kwargs in [
            {"xml": "<x/>\0ignored"},
            {"xml": "<x/>", "previous_invoice_hash": "\0"},
            {"xml": "<x/>", "evaluated_at": "\0"},
        ]:
            with pytest.raises(ValueError, match="interior NUL"):
                validate_zatca_invoice_from_str(config, **kwargs)


def test_fallback_header_declares_owned_report(monkeypatch):
    import fatoora._lib as module

    monkeypatch.setattr(module, "_find_header", lambda: None)
    bindings = module.FfiLibrary()
    result = bindings.lib.fatoora_validate_zatca_invoice_from_str(
        bindings.ffi.NULL, b"<x/>", bindings.ffi.NULL
    )
    assert not result.ok
    bindings.lib.fatoora_error_free(result.error)
