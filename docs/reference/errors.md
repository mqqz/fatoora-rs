---
title: Error codes, exceptions and structured diagnostics
description: Handle fatoority errors using stable codes and JSON details, including validation issues, API failures and partial reports.
---

# Errors and diagnostics

Use error codes and structured fields to decide how to recover. Messages are intended for display and can change; do not parse their wording.

## Shared classification

| Code | Category | Meaning |
| --- | --- | --- |
| 1 | InvalidInput | An argument, key, certificate, option or context is invalid |
| 2 | Validation | A model validation failure or interrupted rule evaluation |
| 3 | Parse | Structured data, a successful API response, or returned cleared XML could not be decoded |
| 4 | Xml | An XML operation failed |
| 5 | Crypto | A cryptographic operation failed |
| 6 | Io | A file or other I/O operation failed |
| 7 | Network | A network operation failed |
| 8 | Unauthorized | The service rejected authorization |
| 9 | Internal | An internal operation failed |
| 10 | Api | A non-authorization API response or acceptance check failed |

Classification follows the cause: an XML failure during signing is `Xml`, while a file-read failure is `Io`. Preserve unknown numeric codes and provide a generic fallback. An `Internal` failure may leave an operation consumed; discard affected operation handles.

## Handle an error

=== "Rust"

    Rust operations return errors for their module: `InvoiceError`, `CsrError`,
    `SigningError`, `QrCodeError`, `InvoiceXmlError`, `ParseError`,
    `XmlValidationError`, `ZatcaValidationError`, `ZatcaError`, `DecimalError`, and
    `EnvironmentParseError`.
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

    **Diagnostics and matching errors**

    Backend failures are converted to `Diagnostic`, which exposes `message()`,
    `file()`, `line()`, `column()`, and `severity()`. Locations and severity are
    optional. Line and column numbers are one-based. Severity is `Warning`, `Error`,
    or `Fatal` when available. Property-file parsing preserves the reported line.
    Backend-specific numeric error codes are outside the public contract.

    Diagnostic wording can change. Use error kinds and structured fields for decisions.

    Public error enums are `#[non_exhaustive]`; downstream matches need a fallback
    arm. New variants can be added. Existing variant fields keep their types and
    meaning; private diagnostic fields can grow behind accessors.

=== "Python"

    Native-operation exceptions inherit from `FfiError` and `FatooraError`. These exceptions
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


    Argument conversion and application code can also raise ordinary Python exceptions, such as `TypeError` or `ValueError`.

    Mapped exception classes are `InvalidInputError`, `ValidationError`, `ParseError`, `XmlError`, `CryptoError`, `IoError`, `NetworkError`, `UnauthorizedError`, `InternalError` and `ApiError`, in numeric code order. Local execution failures may expose a partial validation report at `error.details["report"]`.

=== "JavaScript"

    Native operations throw an `Error` whose `cause` is a `BindingError`.
    Inspect the cause for `code()`, `message()` and `detailsJson()`; parse the
    latter with `JSON.parse`. Transport and application errors can have other causes.

    ```javascript
    import { BindingError } from "fatoority";

    function inspectError(error) {
      if (error?.cause instanceof BindingError) {
        const details = error.cause;
        console.error(details.code(), details.message());
        console.error(JSON.parse(details.detailsJson()));
      } else {
        console.error(error);
      }
    }
    ```

    The error object uses garbage-collected cleanup. A local validation call returning JSON means a report was produced; inspect `is_valid` to decide whether the invoice passed.

=== "C#"

    Native operations throw `BindingErrorException`. Its `Inner` owns a `BindingError`: read `Code()`, `Message()` and `DetailsJson()`, then dispose it. The exception's `Message` is copied text.

    ```csharp
    catch (BindingErrorException error)
    {
        using var details = error.Inner;
        Console.Error.WriteLine($"{details.Code()}: {details.Message()}");
        Console.Error.WriteLine(details.DetailsJson());
    }
    ```

    A returned local validation report still needs its `is_valid` field checked.

=== "Kotlin"

    Native operations throw `BindingException` with `code`, `message` and `detailsJson`. These are copied managed values; the exception needs no cleanup. Parse `detailsJson` with your application's JSON library. Calls on a closed owner throw `IllegalStateException`.

    A returned local validation report still needs its `is_valid` field checked.

=== "Java"

    Native operations throw `BindingException`. Read `getCode()`, `getMessage()` and `getDetailsJson()`. These are copied managed values; the exception needs no cleanup. Calls on a closed owner throw `IllegalStateException`.

    A returned local validation report still needs its `is_valid` field checked.

=== "C"

    The C API uses opaque `FatooraError` owners and a shared `FatooraStatus`:

    ```c
    #include "fatoora.h"

    FatooraStatus fatoora_error_code(const FatooraError *error);
    const char *fatoora_error_message(const FatooraError *error);
    const char *fatoora_error_details_json(const FatooraError *error);
    void fatoora_error_free(FatooraError *error);
    ```

    Pass `FatooraError **error` as the last argument of an operation, or `NULL` when
    only the status matters. `FATOORA_OK` indicates success; other values preserve
    the numeric classification and structured native details. The error's message
    and JSON strings are borrowed until `fatoora_error_free()`. Output slots are
    cleared on entry: release a previous error before reusing its slot.

    C allocation failure can leave the error or its diagnostic strings unavailable;
    use the operation's returned status to decide success. Error accessors accept
    `NULL`: code returns `FATOORA_OK`, message returns an empty string, and details
    returns `{}`. Freeing `NULL` is safe. See [C bindings](bindings/c.md) for allocation and ownership rules.


    For local validation, `FATOORA_OK` means a report was returned; inspect its JSON `is_valid` field. A failure can include a partial report in the error details.

## JSON details

Every details object contains a `type` string. The schema is explicitly mapped
from errors rather than language-specific serialization. Existing field
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

Issue fields use snake_case names for invoice fields. Issue kinds
are `missing`, `empty`, `invalid_format`, `out_of_range`, or `mismatch`.
`line_item_index` is zero-based, or null for an invoice-level issue. Decimal
values are exact strings with insignificant trailing zeroes removed; absent
amounts are null.

| Details type | Structured fields |
| --- | --- |
| `invoice_validation` | `issues`: field, kind, item index, supplied and expected amounts |
| `schema_parse`, `schema_validation` | `diagnostics`: message, optional file, line, column, severity |
| `zatca_validation_execution` | `kind`, optional `stage`, `assertion_site`, `location`, `diagnostics`, and partial `report` |
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
`invalid_vat_format`. Binding-level failures use `{"type":"binding_error"}` with the
classification and message available through their accessors.

Diagnostic location fields may be absent or null. File paths are converted to
UTF-8 lossily when their native encoding cannot be represented. Nested signing
and invoice-import failures retain their underlying validation, serialization,
decimal, or QR details.

### Local ZATCA execution failures

Local validation returns a report for ordinary rejection or incomplete coverage. Inspect `is_valid` before accepting an invoice. `is_complete` describes stage coverage; `has_errors` includes findings obtained before a stage failed. Warnings allow validity once all required stages complete.

Interrupted execution produces an error. Its details have type `zatca_validation_execution` and these fields:

| Field | Meaning |
| --- | --- |
| `kind` | Execution failure kind from the table below |
| `stage` | `xsd`, `cen`, `ksa`, `signature`, `qr`, `previous_invoice_hash`, or null |
| `assertion_site` | Source assertion key, such as `ksa:112:BR-KSA-CL-02`, or null |
| `location` | Shared validation location, including namespace-independent XPath, or null |
| `diagnostics` | One diagnostic containing the execution failure's message |
| `report` | Full report up to the failure, with stage statuses and earlier findings |

| Execution `kind` | Shared classification |
| --- | --- |
| `invalid_xml` | `Xml` (4) |
| `unsupported_xml` | `InvalidInput` (1) |
| `capacity_exceeded` | `InvalidInput` (1) |
| `invalid_context` | `InvalidInput` (1) |
| `rule_evaluation` | `Validation` (2) |
| `schema` | `Parse` (3) |
| `integrity` | `Crypto` (5) |

The `rule_evaluation` classification describes interrupted execution. Ordinary
business-rule violations remain findings in a successfully returned report.
Invalid arguments or malformed options can fail before validation starts and have no partial report. Always allow for that absence. See [invoice validation](invoice-validation.md) for stage applicability and predecessor context.
