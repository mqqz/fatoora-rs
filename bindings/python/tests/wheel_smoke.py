"""Exercise the installed wheel without a source checkout or test fixtures."""

from pathlib import Path

import fatoora
from fatoora import Address, Config, Environment


package = Path(fatoora.__file__).parent
assert (package / "fatoora_ffi.h").is_file(), "wheel must include its matching ABI header"

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

print("Installed wheel loaded its native library and exercised the address API")
