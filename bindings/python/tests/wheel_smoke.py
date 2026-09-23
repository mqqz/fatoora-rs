"""Exercise the installed wheel without a source checkout or test fixtures."""

from pathlib import Path

import fatoora
from fatoora import (
    Address,
    Config,
    Environment,
    InvoiceBuilder,
    InvoiceSubType,
    InvoiceTypeKind,
    VatCategory,
    validate_xml_invoice_from_str,
    validate_zatca_invoice_from_str,
)

package = Path(fatoora.__file__).parent
assert (package / "fatoora_ffi.h").is_file(), (
    "wheel must include its matching ABI header"
)

bundled_libraries = package.parent / "fatoora_rs.libs"
for library, notice in (
    ("*xml2*", "libxml2"),
    ("*lzma*.so*", "xz-libs"),
):
    if any(bundled_libraries.glob(library)):
        assert any((package / "licenses" / notice).glob("*")), (
            f"wheel must include the notice for {library}"
        )

with Config(Environment.NON_PRODUCTION) as config:
    assert config.env() == Environment.NON_PRODUCTION

with Address.new(
    "SA", "Riyadh", "King Fahd", "1234", "12222", district="Olaya"
) as address:
    assert address.district() == "Olaya"

# Build an unsigned standard invoice to exercise embedded schema resources and
# both business-rule profiles without reading source-tree fixtures.
seed = "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ=="
builder = InvoiceBuilder.new(InvoiceTypeKind.TAX, InvoiceSubType.STANDARD)
builder.set_id("WHEEL-1")
builder.set_uuid("123e4567-e89b-12d3-a456-426614174000")
builder.set_issue_datetime("2024-01-01T12:30:00Z")
builder.set_currency("SAR")
builder.set_previous_invoice_hash(seed)
builder.set_invoice_counter(1)
builder.set_payment_means_code("10")
builder.set_vat_category(VatCategory.STANDARD)
builder.set_seller(
    name="Acme Inc",
    country_code="SAU",
    city="Riyadh",
    street="King Fahd",
    building_number="1234",
    postal_code="12222",
    district="Olaya",
    vat_id="399999999900003",
)
builder.add_line_item(
    description="Item",
    quantity="1.0",
    unit_code="PCE",
    unit_price="100.0",
    vat_rate="15.0",
    vat_category=VatCategory.STANDARD,
)
invoice = builder.build()
with Config() as config:
    assert validate_xml_invoice_from_str(config, invoice.xml())
    report = validate_zatca_invoice_from_str(
        config,
        invoice.xml(),
        previous_invoice_hash=seed,
        evaluated_at="2026-09-23T12:00:00+03:00",
    )
    assert report["is_complete"], report
    assert len(report["stages"][1]["evaluated_assertions"]) == 105
    assert len(report["stages"][2]["evaluated_assertions"]) == 152
    assert report["stages"][3]["status"] == "not_applicable"
    assert not validate_zatca_invoice_from_str(config, "<wrong/>")["is_valid"]
for notice in ("LICENSE-LGPL-3.0.txt", "LICENSE-GPL-3.0.txt", "NOTICE.md"):
    assert (package / "licenses/zatca" / notice).is_file(), notice
print("Installed wheel exercised embedded schemas and all 257 business-rule assertions")
