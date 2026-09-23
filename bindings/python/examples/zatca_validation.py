from pathlib import Path

invoice_xml_path = (
    Path(__file__).resolve().parents[3]
    / "fatoora-core/tests/fixtures/sdk-parity/cases/standard-invoice/input.xml"
)

# --8<-- [start:example]
from fatoora import Config, validate_zatca_invoice_from_str

# For later invoices, use the actual predecessor digest from your invoice history.
initial_hash = "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ=="
with Config() as config:
    report = validate_zatca_invoice_from_str(
        config,
        invoice_xml_path.read_text(),
        previous_invoice_hash=initial_hash,
        evaluated_at="2026-09-23T12:00:00+03:00",
    )
assert report["is_valid"]
for stage in report["stages"]:
    for finding in stage["findings"]:
        print(stage["stage"], finding["code"], finding["message"])
# --8<-- [end:example]
