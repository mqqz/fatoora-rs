## fatoora Python bindings

This package wraps Diplomat-generated native bindings with the public `fatoora`
Python API. See [Diplomat bindings](../../docs/development/diplomat.md).

### Development (uv)

```bash
uv venv
uv pip install .
```

### Build a wheel (uv)

```bash
uv build --wheel
```

### Wheels (CI)

- GitHub Actions uses `cibuildwheel` to produce platform wheels in `dist/` (wheel-only publishing).
- See `.github/workflows/python.yml` for the build matrix.

### Notes

- The build step compiles `fatoora-ffi` with `cargo build -p fatoora-ffi --release`.
- The shared library is bundled into the Python package.
- Building the native extension requires CMake and a C++20 compiler. Nanobind is
  pinned in the build dependencies. Reinstall the package after native changes.
- ZATCA API responses are exposed via opaque handles with getters (no JSON payloads).
- Errors are raised as typed exceptions mapped from FFI error codes (see `FfiErrorKind`). Each exception exposes `.code`, `.kind`, and `.details`, a dictionary containing structured validation issues or diagnostics. Unknown codes remain available on a generic `FfiError`.
- Reinstall the package after changes; the extension loads its bundled shared library.

### Examples

```bash
python examples/load_lib.py
python examples/invoice_basic.py
python examples/invoice_parse.py
```

### Tests

```bash
uv pip install -e .[dev]
uv run pytest tests
```

### High-level API

```python
from fatoora import InvoiceBuilder, InvoiceSubType, InvoiceTypeKind, VatCategory

builder = InvoiceBuilder.new(
    invoice_type=InvoiceTypeKind.TAX,
    invoice_subtype=InvoiceSubType.SIMPLIFIED,
)
builder.set_id("INV-1")
builder.set_uuid("123e4567-e89b-12d3-a456-426614174000")
builder.set_issue_datetime("2024-01-01T12:30:00Z")
builder.set_currency("SAR")
builder.set_previous_invoice_hash("hash")
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
print(invoice.xml())
```

`set_issue_datetime` expects a ZATCA ISO UTC timestamp string (`YYYY-MM-DDTHH:MM:SSZ`).
