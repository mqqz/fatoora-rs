---
title: Python ZATCA E-Invoicing Library
description: Python package reference for fatoority. Learn accepted values, returned objects, context managers, errors, validation reports, and ZATCA API methods.
---

# Python package reference

Use Python 3.9 or later. Install `fatoority` and import `fatoora` to build, sign, and validate invoices and
send ZATCA API requests. Start with the [guides](../../guides/validation.md) for
complete workflows; this page describes Python-specific values and behavior.

## Install and import

```sh
python -m pip install fatoority
```

```python
from fatoora import Config, Environment, SigningKey

with Config(Environment.NON_PRODUCTION) as config:
    with SigningKey.generate() as key:
        private_key_pem = key.to_pem()
```

Keep the private key secure. Exported strings and bytes remain in Python memory
after the native owner closes.

The default `Config()` environment is `Environment.NON_PRODUCTION`. Choose
`Environment.SIMULATION` or `Environment.PRODUCTION` explicitly when needed.
Configuration, CSR generation, and credentials must agree on the environment.

## Values and return types

| Value | Python representation |
| --- | --- |
| Text | `str`; embedded NUL is rejected |
| Optional text | `str` or `None`; `""` remains a present empty string |
| Decimal input | `decimal.Decimal`, decimal `str`, or `int`; `float` and `bool` are rejected |
| Decimal output | `decimal.Decimal` |
| Binary input/output | `bytes` |
| Invoice counter | `int` in the unsigned 64-bit range |
| Local ZATCA report | `dict`, already decoded from JSON |
| Line item / totals snapshot | `InvoiceLineItem` / `InvoiceTotals` dataclass |

Use exact decimal text such as `"0.3333"`, rather than constructing a `Decimal`
from a binary float. See [decimal numbers and rounding](../numbers.md).

Public choices use `IntEnum` members. Prefer their names to raw integers:

| Enum | Members |
| --- | --- |
| `Environment` | `NON_PRODUCTION`, `SIMULATION`, `PRODUCTION` |
| `InvoiceTypeKind` | `TAX`, `PREPAYMENT`, `CREDIT_NOTE`, `DEBIT_NOTE` |
| `InvoiceSubType` | `STANDARD`, `SIMPLIFIED` |
| `VatCategory` | `EXEMPT`, `STANDARD`, `ZERO`, `OUT_OF_SCOPE` |
| `InvoiceFlag` | `THIRD_PARTY`, `NOMINAL`, `EXPORT`, `SUMMARY`, `SELF_BILLED` |
| `InvoiceOutcome` | `UNKNOWN`, `ACCEPTED`, `REJECTED` |

Invoice builder timestamps use UTC text such as `"2026-01-01T12:00:00Z"`.
Country/currency values are strings; their constructors validate and normalize
supported values. See the [invoice model](../invoice-model.md).

## Object lifetime

Native owners support `with` and `close()`. Close objects returned by methods as
well as ones you construct. Closing is idempotent; later calls on a closed owner
raise `InvalidInputError`. Calls involving the same owners are synchronized.
Independent owners can be used independently.

`InvoiceBuilder.build()` consumes the builder's inner state even when final
validation fails. `FinalizedInvoice.sign(signer)` consumes the finalized invoice;
`SignedInvoice.into_xml()` consumes the signed invoice. The wrapper remains safe
to close, but further use of consumed state fails. Create a new input object to
retry after a consuming operation fails.

Plain strings, bytes, decimal values, and dataclass snapshots do not need
`close()`. Returned object snapshots are independent of their parent, but still
need their own cleanup.

## Errors

Native failures raise subclasses of `FfiError`, which inherits `FatooraError`.
Use `str(error)` for the message, `.code` for its numeric classification,
`.kind` for `FfiErrorKind`, and `.details` for structured data.

```python
from fatoora import SigningKey
from fatoora.errors import FfiError

try:
    SigningKey.from_pem("invalid key")
except FfiError as error:
    print(error.code, str(error))
    print(error.details)
```

| Category | Exception |
| --- | --- |
| Invalid input | `InvalidInputError` |
| Validation rejection | `ValidationError` |
| Parsing | `ParseError` |
| XML | `XmlError` |
| Cryptography | `CryptoError` |
| File access | `IoError` |
| Network | `NetworkError` |
| Authorization | `UnauthorizedError` |
| Internal failure | `InternalError` |
| API response | `ApiError` |

Unknown native codes produce `FfiError` with `.kind` set to `None`; `.code` and
`.details` remain available. Python argument checks can raise `TypeError` or
`ValueError` before a native call. Do not parse message text to identify an error;
use [error codes and structured details](../errors.md).

## Local validation

| Function | Inputs | Returns |
| --- | --- | --- |
| `validate_xml_invoice_from_str(config, xml)` | `Config`, XML `str` | `True` on schema success; raises on malformed XML or schema rejection |
| `validate_zatca_invoice_from_str(config, xml, *, previous_invoice_hash=None, evaluated_at=None)` | `Config`, XML `str`, optional keyword-only context strings | Report `dict`, including rejection or incomplete coverage |
| `invoice_hash_base64_from_xml_str(xml)` | XML `str` | Base64 invoice hash `str` |

```python
from pathlib import Path
from fatoora import Config, validate_zatca_invoice_from_str

xml = Path("invoice.xml").read_text(encoding="utf-8")
with Config() as config:
    report = validate_zatca_invoice_from_str(config, xml)
print(report["is_valid"], report["is_complete"])
```

`previous_invoice_hash` supplies trusted invoice-history context. `evaluated_at`
accepts an RFC3339 timestamp; omission uses one UTC clock snapshot. Missing
predecessor context makes coverage incomplete. A returned dictionary does not
mean the invoice passed: inspect `is_valid` and the stage findings.

Execution failures raise an exception and may include a partial report at
`error.details["report"]`. Argument failures can have no report. All schemas are
bundled; validation needs no network or external SDK. It does not establish
remote acceptance or certificate issuer trust. See the
[validation reference](../invoice-validation.md).

## ZATCA API methods

Create `ZatcaClient(config)` with a live `Config`. Client methods block the
calling thread and return owned objects:

| Method | Inputs | Returns |
| --- | --- | --- |
| `post_csr_for_ccsid(csr, otp)` | `Csr`, OTP `str` | `CsidCompliance` |
| `post_ccsid_for_pcsid(ccsid)` | `CsidCompliance` | `CsidProduction` |
| `renew_csid(pcsid, csr, otp, accept_language=None)` | `CsidProduction`, `Csr`, OTP, optional language | `CsidProduction` |
| `check_invoice_compliance(invoice, ccsid)` | `SignedInvoice`, `CsidCompliance` | `ValidationResponse` |
| `report_simplified_invoice(invoice, pcsid, clearance_status, accept_language=None)` | `SignedInvoice`, `CsidProduction`, Boolean, optional language | `ValidationResponse` |
| `clear_standard_invoice(invoice, pcsid, clearance_status, accept_language=None)` | `SignedInvoice`, `CsidProduction`, Boolean, optional language | `ValidationResponse` |

`clearance_status` is a required Boolean controlling the request header; use
`False` for ordinary reporting and `True` for clearance. It does not describe the
result. `accept_language` is a string or `None` controlling the language header.
These methods do not expose an asynchronous or cancellation-token parameter.

A successful HTTP request does not guarantee acceptance. Call `outcome()` to
obtain `InvoiceOutcome`, or `ensure_accepted()` to raise for rejected/unknown
outcomes. `cleared_invoice_xml()` returns `str | None`; save that XML for an
accepted clearance when present. `reporting_status()` and `clearance_status()`
also return optional strings. See [API request and response contracts](../api-client.md)
and the [API guide](../../guides/api.md).

## Signed invoice metadata

| Method | Returns |
| --- | --- |
| `signature()` | Encoded signature `str` |
| `public_key()` | Encoded public key `str` |
| `cert_hash()` | Encoded certificate hash `str` |
| `signed_props_hash()` | Encoded signed-properties hash `str` |
| `signing_time()` | UTC `str` formatted `YYYY-MM-DDTHH:MM:SS` |

Parsing a signed invoice extracts these values; it does not verify authenticity.
Use explicit validation when you need integrity checks. See the
[signing reference](../invoice-signing.md) for key/certificate formats and signing operations.
