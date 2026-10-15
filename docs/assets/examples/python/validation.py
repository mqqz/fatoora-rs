from pathlib import Path
import json
import sys
from fatoora.config import Config, Environment
from fatoora.validation import validate_xml_invoice_from_str, validate_zatca_invoice_from_str

xml = Path("invoice.xml").read_text(encoding="utf-8")
with Config(Environment.NON_PRODUCTION) as config:
    if "--zatca" in sys.argv:
        report = validate_zatca_invoice_from_str(
            config, xml,
            previous_invoice_hash=Path("previous-hash.txt").read_text().strip(),
        )
        print(json.dumps(report, indent=2))
        sys.exit(0 if report["is_valid"] else 1)
    validate_xml_invoice_from_str(config, xml)
    print("XSD valid")
