from pathlib import Path
from fatoora.invoice import parse_signed_invoice_xml

xml = Path("signed.xml").read_text(encoding="utf-8")
with parse_signed_invoice_xml(xml) as invoice:
    payload = invoice.qr_code()
Path("qr.txt").write_text(payload, encoding="utf-8")
print(payload)
