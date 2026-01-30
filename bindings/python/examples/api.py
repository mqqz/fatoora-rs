from pathlib import Path
signed_xml_path = Path(__file__).resolve().parents[3] / "fatoora-core" / "tests" / "fixtures" / "invoices" / "sample-simplified-invoice.xml"

# --8<-- [start:example]
from fatoora.api import CsidCompliance, ZatcaClient
from fatoora.config import Config, Environment
from fatoora.invoice import parse_signed_invoice_xml

# signed_xml_path = "path/to/signed_invoice.xml"
config = Config(Environment.NON_PRODUCTION)
signed = parse_signed_invoice_xml(signed_xml_path.read_text(encoding="utf-8"))

client = ZatcaClient(config)
ccsid = CsidCompliance.new(
    Environment.NON_PRODUCTION,
    "binary_security_token",
    "secret",
    "1234567890",
)
hash_b64 = signed.hash_base64()
assert hash_b64
# --8<-- [end:example]
