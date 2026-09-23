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


def test_response_children_remain_owned_after_parents_close(monkeypatch):
    from fatoora import _native
    from fatoora.errors import InvalidInputError

    body = json.dumps({"validationResults": {
        "status": "PASS", "infoMessages": {"code": "INFO", "message": "retained"},
        "warningMessages": [{"code": "WARN"}], "errorMessages": []
    }, "reportingStatus": "REPORTED"})
    with gateway(monkeypatch, 200, body):
        response = report()
    results = response.validation_results()
    response.close()
    with pytest.raises(InvalidInputError):
        response.http_status()
    assert results.status() == "PASS"
    messages = results.info_messages()
    assert len(messages) == 1
    assert results.warning_messages()[0].code() == "WARN"
    assert results.error_messages() == []
    for method, index in [("info_message", 1), ("warning_message", 1), ("error_message", 0)]:
        with pytest.raises(Exception) as caught:
            getattr(results._handle, method)(index)
        error = caught.value.args[0]
        assert isinstance(error, _native.BindingError)
        assert error.code() == 1
    results.close()
    assert messages[0].code() == "INFO"
    assert messages[0].message() == "retained"
    messages[0].close()


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


@pytest.mark.parametrize("invoice_action", ["into_xml", "close"])
def test_http_releases_gil_and_retains_locked_arguments(invoice_action):
    # A subprocess bounds failures even if a regression holds the GIL forever.
    import subprocess
    import sys
    import textwrap

    fixture = Path(__file__).resolve().parents[3] / "fatoora-core/tests/fixtures/invoices/sample-simplified-invoice.xml"
    script = textwrap.dedent(r'''
        import base64
        import json
        import os
        from pathlib import Path
        import sys
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from threading import Event, Thread
        from fatoora import CsidProduction, ZatcaClient, parse_signed_invoice_xml
        from fatoora.config import Config, Environment
        from fatoora.errors import InvalidInputError

        received, release = Event(), Event()
        captured, failures, responses, consumed = {}, [], [], []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                captured["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                captured["authorization"] = self.headers["Authorization"]
                received.set()
                if not release.wait(8):
                    failures.append("request was never released")
                payload = b'{"validationResults":{"status":"PASS"},"reportingStatus":"REPORTED"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        os.environ["FATOORA_ZATCA_BASE_URL"] = f"http://127.0.0.1:{server.server_port}"
        xml = Path(sys.argv[1]).read_text()
        invoice = parse_signed_invoice_xml(xml)
        credentials = CsidProduction.new(Environment.NON_PRODUCTION, "test-token", "test-secret")
        client = ZatcaClient(Config(Environment.NON_PRODUCTION))
        def request():
            try:
                responses.append(client.report_simplified_invoice(invoice, credentials, False, "en"))
            except BaseException as exc:
                failures.append(repr(exc))
        request_thread = Thread(target=request, daemon=True)
        request_thread.start()
        mutation_threads = []
        try:
            assert received.wait(5), "HTTP operation blocked Python gateway: GIL was not released"
            for owner, action in [(invoice, sys.argv[2]), (credentials, "close"), (client, "close")]:
                started, finished = Event(), Event()
                def mutate(owner=owner, action=action, started=started, finished=finished):
                    started.set()
                    try:
                        value = getattr(owner, action)()
                        if action == "into_xml":
                            consumed.append(value)
                    except BaseException as exc:
                        failures.append(repr(exc))
                    finally:
                        finished.set()
                thread = Thread(target=mutate, daemon=True)
                mutation_threads.append(thread)
                thread.start()
                assert started.wait(2), "mutation thread was not scheduled"
                assert not finished.wait(0.15), f"{action} invalidated an argument during HTTP"
            release.set()
            request_thread.join(5)
            assert not request_thread.is_alive(), "HTTP request did not finish"
            for thread in mutation_threads:
                thread.join(3)
                assert not thread.is_alive(), "argument lock was not released"
            assert not failures, failures
            assert len(responses) == 1
            responses[0].ensure_accepted()
            assert responses[0].http_status() == 200
            responses[0].close()
            assert base64.b64decode(captured["body"]["invoice"]).decode() == xml
            assert captured["authorization"] == "Basic " + base64.b64encode(b"test-token:test-secret").decode()
            if sys.argv[2] == "into_xml":
                assert consumed == [xml]
            for method in (invoice.xml, credentials.secret):
                try:
                    method()
                except InvalidInputError:
                    pass
                else:
                    raise AssertionError("closed or consumed object remained usable")
        finally:
            release.set()
            request_thread.join(2)
            for thread in mutation_threads:
                thread.join(2)
            server.shutdown()
            server.server_close()
            server_thread.join(2)
    ''')
    result = subprocess.run(
        [sys.executable, "-c", script, str(fixture), invoice_action],
        capture_output=True, text=True, timeout=25,
    )
    assert result.returncode == 0, result.stdout + result.stderr
