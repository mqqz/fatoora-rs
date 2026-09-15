# Errors

Rust operations return errors for their module: `InvoiceError`, `CsrError`,
`SigningError`, `QrCodeError`, `InvoiceXmlError`, `ParseError`,
`XmlValidationError`, `ZatcaError`, `DecimalError`, and `EnvironmentParseError`.
Each has a `kind()` method for shared classification.

Convert a module error into `fatoora_core::Error` when combining operations.
The conversion retains the original error, including validation issues and API
responses. `Display` provides a human-readable message; `details_json()` provides
the binding representation.

```rust
use fatoora_core::{Error, ErrorKind};
use fatoora_core::invoice::{InvoiceError, InvoiceBuilder};

fn build(builder: InvoiceBuilder) -> Result<(), Error> {
    let _invoice = builder.build()?;
    Ok(())
}

fn inspect(error: &Error) {
    if let Error::Invoice(InvoiceError::Validation(validation)) = error {
        for issue in validation.issues() {
            eprintln!("{:?}: {:?}", issue.field(), issue.kind());
        }
    }
    if error.kind() == ErrorKind::Validation {
        eprintln!("{}", error.details_json());
    }
}
```

## Shared classification

These codes are stable across Rust, C, and Python. New categories may be added;
consumers must retain unknown numeric codes and provide a generic fallback.

| Code | Rust / C category | Python exception |
| --- | --- | --- |
| 1 | InvalidInput | InvalidInputError |
| 2 | Validation | ValidationError |
| 3 | Parse | ParseError |
| 4 | Xml | XmlError |
| 5 | Crypto | CryptoError |
| 6 | Io | IoError |
| 7 | Network | NetworkError |
| 8 | Unauthorized | UnauthorizedError |
| 9 | Internal | InternalError |
| 10 | Api | ApiError |

Classification follows the cause: an XML failure during signing is `Xml`, and a
file-read failure is `Io`. Invalid certificate or key input is `InvalidInput`.

## Owned diagnostics and evolution

Backend failures are converted to `Diagnostic`, which exposes `message()`,
`file()`, `line()`, `column()`, and `severity()`. Locations and severity are
optional. Line and column numbers are one-based. Severity is `Warning`, `Error`,
or `Fatal` when available. Property-file parsing preserves the reported line.
Backend-specific numeric error codes are outside the public contract.

Public error payloads and source chains use crate-owned or standard-library
types. They do not expose third-party backend objects or public conversions from
backend errors. Diagnostic wording can change with backend versions.

Public error enums are `#[non_exhaustive]`; downstream matches need a fallback
arm. New variants can be added. Existing variant fields keep their types and
meaning; private diagnostic fields can grow behind accessors.

## C ownership

`FfiError` is opaque. Access it only through these functions:

```c
int32_t fatoora_error_code(struct FfiError *error);
struct FfiString fatoora_error_message(struct FfiError *error);
struct FfiString fatoora_error_details_json(struct FfiError *error);
void fatoora_error_free(struct FfiError *error);
```

A failed `FfiResult` owns an error handle. Free it exactly once. Each message or
JSON accessor returns a separate UTF-8, NUL-terminated string; free each copy with
`fatoora_string_free`. Copies remain valid after freeing the error handle.
Embedded NULs in messages are displayed as `\0`; JSON preserves them as escapes.
A null error handle returns code zero and null strings; freeing null is allowed.

Fallible C entrypoints catch unwinding Rust panics and return `Internal`.
Builds using `panic=abort`, allocation failure, and invalid foreign pointers
cannot be recovered this way. A caller must still obey pointer and handle
ownership requirements. An operation that panics is not guaranteed to roll back
its mutations; discard affected operation handles after an `Internal` failure.

## JSON details

Every details object contains a `type` string. The schema is explicitly mapped
from owned errors; it is independent of Rust enum serialization. Existing field
meanings and discriminator strings are stable. Additional fields and types may
be added. Consumers must ignore unknown fields and handle unknown types.
Messages are for display and must not be parsed for classification.

An invoice validation failure looks like this:

```json
{
  "type": "invoice_validation",
  "issues": [
    {
      "field": "line_item_vat_amount",
      "kind": "mismatch",
      "line_item_index": 0,
      "supplied": "10",
      "expected": "15"
    }
  ]
}
```

Issue fields use snake_case names corresponding to `InvoiceField`. Issue kinds
are `missing`, `empty`, `invalid_format`, `out_of_range`, or `mismatch`.
`line_item_index` is zero-based, or null for an invoice-level issue. Decimal
values are exact strings with insignificant trailing zeroes removed; absent
amounts are null.

| Details type | Structured fields |
| --- | --- |
| `invoice_validation` | `issues`: field, kind, item index, supplied and expected amounts |
| `schema_parse`, `schema_validation` | `diagnostics`: message, optional file, line, column, severity |
| `xml_serialize`, `signing_xml`, `signing_input` | `diagnostics` |
| `api_response` | `http_status`: actual HTTP status; `body`: response text; `response`: complete parsed JSON or null |
| `api_response_decode` | `http_status`, `body`, `message` for a malformed 2xx response |
| `api_response_read` | `http_status`, `message` for a failed response-body read |
| `api_not_accepted` | `http_status` or null, `outcome`: rejected or unknown, `response`: typed validation body |
| `api_cleared_invoice` | `http_status` or null, `message` for invalid cleared-invoice content |
| `api_unauthorized` | `response`: timestamp, status, error, message |
| `api_server` | `response`: category, code, message |
| `missing_property` | `path`, `key` |
| `properties_parse` | `path`, `diagnostics` |
| `io` | `path`, `diagnostics` |
| `der_encode` | `context`, `diagnostics` |
| `csr_extension` | `extension`, `diagnostics` |
| `missing_field` | `field` |
| `invalid_value` | `field`, `value` |
| `invalid_xsd_path` | `path` |
| `invalid_environment`, `invalid_country_code`, `invalid_currency_code`, `invalid_timestamp`, `invalid_issue_date` | `value` |
| `qr_value_too_long` | `tag`, `length`, `limit` (255 bytes) |
| `qr_encoded_too_long` | `length`, `limit` (700 encoded characters) |

Message-only failures use `diagnostics` containing a message. Their types are
`xml_parse`, `xpath`, `qr_xml`, `signing`, `invalid_subject`, `invalid_san`,
`csr_request`, `csr_build`, `key_decode`, `key_encode`, `csr_validation`,
`network`, `invalid_response`, `http`, and `client_state`.

Types without additional fields are `invalid_decimal`, `decimal_out_of_range`,
`missing_seller_vat`, `missing_seller_name`, `missing_buyer_id`, and
`invalid_vat_format`. FFI-specific failures use `{"type":"error"}` with the
classification and message available through their accessors.

Diagnostic location fields may be absent or null. File paths are converted to
UTF-8 lossily when their native encoding cannot be represented. Nested signing
and invoice-import failures retain their underlying validation, serialization,
decimal, or QR details.

## Python

All binding exceptions inherit from `FfiError` and `FatooraError`. Exceptions
carry `.code`, `.kind`, and `.details`. Unknown codes produce `FfiError`, with
`.kind` set to `None`; the original code and details remain available.

```python
from fatoora import InvoiceBuilder, InvoiceSubType, InvoiceTypeKind
from fatoora.errors import ValidationError

builder = InvoiceBuilder.new(InvoiceTypeKind.TAX, InvoiceSubType.SIMPLIFIED)
try:
    builder.build()
except ValidationError as error:
    for issue in error.details.get("issues", []):
        print(issue["field"], issue["kind"])
```

## Migrating existing callers

Use `error.to_string()` instead of `Error::message()`. `Error` wraps module errors
and no longer has the `new(kind, message)` constructor or `Clone`/`Eq` derives.
Convert an operation's error with `?` or `.into()`.

Replace `signer.certificate()` with `signer.certificate_der()` or
`signer.certificate_pem()`. These return owned bytes or text and `SigningError`
on failure. C and Python retain their existing certificate export functions.

`InvoiceFlags` now wraps its bitflags implementation privately. Its constants,
bit operations, JSON representation, and iteration remain available through
crate-owned types. Code that used the `bitflags::Flags` trait or named bitflags
iterator types must use the `InvoiceFlags` methods and owned iterators instead.

Rebuild bindings against the matching library and generated headers. Code that
accessed `FfiError` fields directly must use the accessors. Bindings must not
allocate error handles or depend on their layout.
