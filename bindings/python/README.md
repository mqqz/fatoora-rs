## fatoora Python bindings

This package wraps the `fatoora-ffi` shared library via `cffi`.

### Development (uv)

```bash
uv venv
uv pip install -e .
```

### Build a wheel (uv)

```bash
uv pip wheel .
```

### Wheels (CI)

- GitHub Actions uses `cibuildwheel` to produce platform wheels in `dist/`.
- See `.github/workflows/python-wheels.yml` for the build matrix.

### Notes

- The build step compiles `fatoora-ffi` with `cargo build -p fatoora-ffi --release`.
- The shared library is bundled into the Python package.
- For local dev without install, set `FATOORA_FFI_PATH` or build and use the repo `target/` output.
- If a `fatoora_ffi.h` header is present (from `FATOORA_CBINDGEN=1 cargo build -p fatoora-ffi`),
  the Python wrapper will load its declarations automatically. You can override the header with
  `FATOORA_FFI_HEADER=/path/to/fatoora_ffi.h`.

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
from datetime import datetime, timezone
from fatoora import InvoiceBuilder, InvoiceSubType, InvoiceTypeKind, VatCategory

builder = InvoiceBuilder.new(
    invoice_type=InvoiceTypeKind.TAX,
    invoice_subtype=InvoiceSubType.SIMPLIFIED,
    invoice_id="INV-1",
    uuid="123e4567-e89b-12d3-a456-426614174000",
    issue_datetime=datetime.now(timezone.utc),
    currency_code="SAR",
    previous_invoice_hash="hash",
    invoice_counter=1,
    payment_means_code="10",
    vat_category=VatCategory.STANDARD,
    seller_name="Acme Inc",
    seller_country_code="SAU",
    seller_city="Riyadh",
    seller_street="King Fahd",
    seller_building_number="1234",
    seller_postal_code="12222",
    seller_vat_id="399999999900003",
)
builder.add_line_item(
    description="Item",
    quantity=1.0,
    unit_code="PCE",
    unit_price=100.0,
    vat_rate=15.0,
    vat_category=VatCategory.STANDARD,
)
invoice = builder.build()
print(invoice.xml())
```
