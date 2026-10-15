from pathlib import Path
from fatoora.sign import Signer

xml = Path("invoice.xml").read_text(encoding="utf-8")
certificate = Path("certificate.pem").read_text(encoding="utf-8")
key = Path("private-key.pem").read_text(encoding="utf-8")
with Signer.from_pem(certificate, key) as signer:
    signed_xml = signer.sign_xml(xml)
Path("signed.xml").write_text(signed_xml, encoding="utf-8")
print("Saved signed.xml")
