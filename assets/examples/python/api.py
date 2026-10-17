from pathlib import Path
import os
from fatoora.api import CsidProduction, ZatcaClient
from fatoora.config import Config, Environment
from fatoora.invoice import parse_signed_invoice_xml

# Use credentials issued for this same environment.
environment = Environment.NON_PRODUCTION
token = os.environ["ZATCA_TOKEN"]
secret = os.environ["ZATCA_SECRET"]
with Config(environment) as config, ZatcaClient(config) as client:
    with CsidProduction.new(environment, token, secret, None) as credentials:
        with parse_signed_invoice_xml(Path("signed.xml").read_text(encoding="utf-8")) as invoice:
            with client.report_simplified_invoice(invoice, credentials, False, "en") as response:
                response.ensure_accepted()
                print("Invoice reporting accepted")
