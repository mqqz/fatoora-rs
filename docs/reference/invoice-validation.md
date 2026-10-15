# Invoice Validation

C signatures use the [C API](../development/c-api.md). See [C and C++ bindings](bindings/c.md) for ownership and build instructions.
The declarations below come from the generated headers. C++ exposes the same types
in namespace `fatoora` through `fatoora/Type.hpp` headers.

Explicit schema and local ZATCA validation for original invoice XML.


## Construction, parsing, and validation

These operations establish different guarantees:

| Operation | Guarantee |
| --- | --- |
| Validated wrapper constructor or deserialization | Validation and normalization implemented by that wrapper |
| `build()` | Selected field, range, and amount checks; computed totals |
| XML parsing | Supported fields, wrapper and builder checks, and modeled supplied amounts |
| XSD validation | Conformance to the bundled UBL schema |
| Explicit ZATCA validation | Pinned SDK rule profiles and applicable local integrity checks, with stage coverage |
| Signing | Generates signature material |
| Parsing a signed invoice | Extracts signature material without verifying authenticity |

`FinalizedInvoice` does not imply full business-rule compliance. `SignedInvoice`
may come from parsing and does not prove its signature was verified. No local
operation establishes remote acceptance or certificate issuer trust.

`CountryCode`, `CurrencyCode`, `InvoiceTimestamp`, `InvoiceDate`, and `VatId`
deserialize through their constructors with the same normalization. Invalid
values are rejected according to each wrapper's checks. `VatId` currently checks
only that the trimmed value is nonempty.


## `validate_xml_invoice_from_str`

### `validate`

???+ note "Validate invoice XML"
    Validate invoice XML against the bundled UBL schema.

    === "{{ lang.rust }}"
        ```rust
        validate_xml_invoice_from_str(xml: &str, config: &Config) -> Result<(), XmlValidationError>
        ```

    === "{{ lang.python }}"
        ```python
        validate_xml_invoice_from_str(config: Config, xml: str) -> bool
        ```

    === "{{ lang.c }}"
        ```c
        #include "fatoora.h"

        FatooraStatus fatoora_xml_validate(const FatooraConfig *config,
            const char *xml,
            bool *out,
            FatooraError **error);
        ```

## Behavior

!!! note "Behavior"
    - Validation uses the bundled UBL 2.1 schema under `fatoora-core/assets`.
    - Errors include schema parse failures, XML parse failures, and schema validation errors.
    - XML parsing disables recovery: malformed XML is rejected rather than repaired.

See also: [Invoice Validation Guide](../guides/validation.md)

## Validation reports (Rust)

`validate_xml_invoice_report_from_str(xml, config)` returns
`Result<ValidationReport, XmlValidationError>` and runs only XSD validation.
The existing Rust, C, and Python validation APIs keep their current return types.

```rust
use fatoora_core::config::Config;
use fatoora_core::invoice::validation::{
    validate_xml_invoice_report_from_str, ValidationLayer,
};

fn example(xml: &str) -> Result<(), Box<dyn std::error::Error>> {
    let report = validate_xml_invoice_report_from_str(xml, &Config::default())?;
    assert_eq!(report.layers_checked, vec![ValidationLayer::Xsd]);
    for issue in &report.issues {
        println!("{}: {} ({:?})", issue.code, issue.message, issue.location);
    }
    if report.has_errors() {
        // Handle schema violations.
    }
    Ok(())
}
```

- `layers_checked` lists completed layers, including layers that found errors.
  An absent layer makes no claim. An empty report does not imply compliance.
- Each finding has `layer`, `code`, `severity`, `message`, and optional `location`.
- Severities are `Warning` and `Error`; backend fatal diagnostics become errors.
- Codes are stable library-owned identifiers. Message wording is not stable.
  Field codes are `FIELD_REQUIRED`, `FIELD_EMPTY`, `FIELD_INVALID_FORMAT`,
  `FIELD_OUT_OF_RANGE`, and `FIELD_MISMATCH`. Schema findings use `XSD_INVALID`.
  Official business-rule codes are reserved for implementations of those rules.
- Field locations use model paths such as `line_items[0].quantity` with zero-based
  indices. XML locations use one-based line and optional column numbers. Missing
  locations remain `None`; the ZATCA business-rule validator supplies XPath locations.
- Schema violations return `Ok(report)` with errors. Schema setup failures and
  malformed XML return `Err`, because XSD validation did not complete.
- The explicit ZATCA report can aggregate completed `BusinessRules`, `Signature`,
  `Qr`, and `PreviousInvoiceHash` layers. XSD-only APIs never claim those checks.

Convert a builder `ValidationError` with `ValidationReport::from(&error)`, or an
individual `ValidationIssue` with `ValidationFinding::from(&issue)`. These
conversions preserve existing error APIs and do not execute additional checks.
Existing structured supplied/expected amounts remain available on the original
issue and are included in the finding message when present.

## Local ZATCA report

```rust
validate_zatca_invoice_from_str(
    xml: &str,
    config: &Config,
    options: &ZatcaValidationOptions,
) -> Result<ZatcaValidationReport, ZatcaValidationError>
```

```python
validate_zatca_invoice_from_str(
    config: Config, xml: str, *,
    previous_invoice_hash: str | None = None,
    evaluated_at: str | None = None,
) -> dict
```

```c
#include "fatoora.h"

FatooraStatus fatoora_xml_validate_zatca(const FatooraConfig *config,
    const char *xml,
    const char *options_json,
    char **out,
    FatooraError **error);
```

C accepts `NULL` options for defaults, or a JSON string containing
`previous_invoice_hash` and `evaluated_at`. Inputs are NUL-terminated UTF-8
strings. Options JSON is limited to 4 KiB. The report is returned as owned JSON
text through `char **out`. Release it with `fatoora_string_free()` and errors with
`fatoora_error_free()`. `FATOORA_OK` means a report was produced; inspect its `is_valid` field before
accepting the document. Python returns the same report dictionary and rejects
interior NULs before entering native code.

The report contains `schema_version: 1`, `profile: "zatca-sdk-238-R3.4.8"`, the
clock snapshot, and ordered `stages`: `xsd`, `cen`, `ksa`, `signature`, `qr`,
`previous_invoice_hash`. Each stage has a status, findings, optional source
provenance, and evaluated assertion sites. Findings reuse the shared format and
add `assertion_site`; business-rule locations use namespace-aware XPath strings.
JSON includes computed `is_complete`, `has_errors`, and `is_valid` booleans. Rust
provides methods with those names. Deserialization recomputes those outcomes.

| Stage status | Meaning |
| --- | --- |
| `completed` | The stage finished; findings can include errors |
| `not_run` | Dependencies failed or execution stopped earlier |
| `not_applicable` | SDK profile skips signature/QR for standard invoices |
| `context_required` | Predecessor hash was not supplied |
| `evaluation_failed` | Evaluation stopped; findings may be partial |

`is_valid` requires complete coverage and no error findings. Warnings are retained.
Schema rejection returns a report and skips dependent stages. Malformed XML,
unsupported DTDs, capacity limits, and rule execution failures return an error
carrying the partial report. Python exposes that report in `exception.details`;
see [error details](errors.md#local-zatca-execution-failures).

The default evaluation time is captured once in UTC. `evaluated_at` accepts an
RFC3339 instant and offset. Predecessor context must be canonical base64 of a
SHA-256 digest, or the SDK's base64 hexadecimal digest representation. The
validator compares it with the invoice's PIH; it cannot obtain invoice history.

CEN/KSA source hashes and all 257 assertion sites are pinned. Integrity checks
constrain algorithms and references, verify the embedded key against the invoice
signature, and bind QR fields to the invoice and certificate. They establish no
issuer trust, certificate revocation status, or remote acceptance. The
[development guide](../development/business-rules.md) lists resource limits and
intentional differences from the SDK's integrity checks. Runtime needs no Java,
SDK files or network access; schema compilation uses only embedded resources in memory.
