from pathlib import Path

invoice_xml_path = (
    Path(__file__).resolve().parents[3]
    / "fatoora-core"
    / "tests"
    / "fixtures"
    / "invoices"
    / "sample-simplified-invoice.xml"
)

# --8<-- [start:example]
from fatoora.config import Config
from fatoora.validation import validate_xml_invoice_from_str

# invoice_xml_path = "path/to/invoice.xml"
config = Config()
xml = invoice_xml_path.read_text(encoding="utf-8")

result = validate_xml_invoice_from_str(config, xml)
assert result is True
# --8<-- [end:example]
