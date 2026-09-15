"""Exercise the public Python API through the shared library and a loopback gateway."""
import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread

import pytest
from fatoora import CsidProduction, ZatcaClient, InvoiceOutcome, parse_signed_invoice_xml
from fatoora.config import Config, Environment
from fatoora.errors import ApiError, ParseError, UnauthorizedError


@contextmanager
def gateway(monkeypatch, status, body):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("FATOORA_ZATCA_BASE_URL", f"http://127.0.0.1:{server.server_port}")
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def report():
    fixture = Path(__file__).resolve().parents[3] / "fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml"
    with parse_signed_invoice_xml(fixture.read_text()) as invoice, \
         CsidProduction.new(Environment.NON_PRODUCTION, "test-token", "test-secret") as credentials, \
         ZatcaClient(Config(Environment.NON_PRODUCTION)) as client:
        return client.report_simplified_invoice(invoice, credentials, False, "en")


@pytest.mark.parametrize("status", [400, 409, 401, 503])
def test_http_error_details_survive_native_boundary(monkeypatch, status):
    body = json.dumps({"validationResults": {"status": "ERROR", "errorMessages": [{"code": "BR-KSA-37"}]}, "reportingStatus": "NOT_REPORTED", "futureField": "preserved"})
    with gateway(monkeypatch, status, body), pytest.raises(UnauthorizedError if status == 401 else ApiError) as caught:
        report()
    details = caught.value.details
    assert details["http_status"] == status
    assert details["body"] == body
    assert details["response"]["futureField"] == "preserved"
    assert details["response"]["validationResults"]["errorMessages"][0]["code"] == "BR-KSA-37"


@pytest.mark.parametrize("wire_status,outcome", [("REPORTED", InvoiceOutcome.ACCEPTED), ("NOT_REPORTED", InvoiceOutcome.REJECTED), ("NEW_STATUS", InvoiceOutcome.UNKNOWN)])
def test_receipt_outcome_and_copied_invoice(monkeypatch, wire_status, outcome):
    xml = "<Invoice>\n  exact text\n</Invoice>\n"
    encoded = base64.b64encode(xml.encode()).decode()
    body = json.dumps({"validationResults": {"status": "WARNING", "warningMessages": [{"code": "warning"}]}, "reportingStatus": wire_status, "clearedInvoice": encoded})
    with gateway(monkeypatch, 202, body), report() as response:
        assert response.http_status() == 202
        assert response.outcome() == outcome
        copied = response.cleared_invoice_xml()
        assert response.cleared_invoice_base64() == encoded
        if outcome == InvoiceOutcome.ACCEPTED:
            response.ensure_accepted()
        else:
            with pytest.raises(ApiError) as caught:
                response.ensure_accepted()
            assert caught.value.details["outcome"] == outcome.name.lower()
            assert caught.value.details["http_status"] == 202
    assert copied == xml


@pytest.mark.parametrize("value", [None, "", "%%%", "/w==", "AA=="])
def test_cleared_invoice_missing_and_invalid(monkeypatch, value):
    body = json.dumps({"validationResults": {}, "reportingStatus": "REPORTED", "clearedInvoice": value})
    with gateway(monkeypatch, 200, body), report() as response:
        if value is None:
            assert response.cleared_invoice_base64() is None
            assert response.cleared_invoice_xml() is None
        else:
            assert response.cleared_invoice_base64() == value
            with pytest.raises(ParseError) as caught:
                response.cleared_invoice_xml()
            assert caught.value.details["http_status"] == 200
            assert caught.value.details["type"] == "api_cleared_invoice"


def test_bundled_response_declarations(monkeypatch):
    import fatoora._lib as module
    monkeypatch.setattr(module, "_find_header", lambda: None)
    bindings = module.FfiLibrary()
    for name in ["http_status", "outcome", "ensure_accepted", "cleared_invoice_base64", "cleared_invoice_xml"]:
        result = getattr(bindings.lib, "fatoora_validation_response_" + name)(bindings.ffi.NULL)
        assert not result.ok
        bindings.lib.fatoora_error_free(result.error)


def test_api_example_checks_acceptance_against_local_gateway(monkeypatch):
    import runpy
    body = '{"validationResults":{"status":"PASS"},"reportingStatus":"REPORTED"}'
    example = Path(__file__).resolve().parents[1] / "examples/api.py"
    with gateway(monkeypatch, 200, body):
        namespace = runpy.run_path(str(example), run_name="__main__")
        namespace["response"].close()
        namespace["client"].close()
        namespace["pcsid"].close()
        namespace["signed"].close()
