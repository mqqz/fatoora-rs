"""Exercise the installed wheel without a source checkout or test fixtures."""

from pathlib import Path

import fatoora
from fatoora import Address, Config, Environment


package = Path(fatoora.__file__).parent
assert not (package / "_lib.py").exists(), "wheel must not retain the legacy loader"
assert not (package / "fatoora_ffi.h").exists(), "wheel must not retain legacy declarations"
from fatoora import _native
assert _native.__file__

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

from fatoora import InvoiceBuilder, InvoiceTypeKind, InvoiceSubType, VatCategory
from fatoora.errors import InvalidInputError

maps = Path("/proc/self/maps")
if maps.exists():
    loaded = [line.split()[-1] for line in maps.read_text().splitlines() if "libfatoora_ffi" in line]
    assert loaded and all(Path(path).parent in (package, bundled_libraries) for path in loaded), loaded

builder = InvoiceBuilder.new(InvoiceTypeKind.TAX, InvoiceSubType.SIMPLIFIED)
builder.set_id("INV-1")
builder.set_uuid("8e6000cf-1a98-4174-b3e7-b5d5954bc10d")
builder.set_issue_datetime("2024-01-01T12:30:00Z")
builder.set_previous_invoice_hash("hash")
builder.set_invoice_counter(1)
builder.set_currency("SAR")
builder.set_payment_means_code("10")
builder.set_vat_category(VatCategory.STANDARD)
builder.set_seller(name="Seller", vat_id="399999999900003", country_code="SA", city="Riyadh",
                   street="King Fahd", building_number="1234", postal_code="12222")
builder.add_line_item("Item", 3, "PCE", "0.3333", 15, VatCategory.STANDARD)
xml = builder.build().xml()
assert ">1.15</cbc:TaxInclusiveAmount>" in xml
try:
    builder.build()
except InvalidInputError as error:
    assert error.code == 1 and error.details["type"] == "binding_error"
else:
    raise AssertionError("consumed builder must fail")
print("Installed wheel exercised generated bindings and bundled library")

from fatoora import SigningKey
with SigningKey.generate() as key:
    der = key.to_der()
    assert isinstance(der, bytes) and der
with SigningKey.from_der(der) as restored:
    assert restored.to_der() == der
