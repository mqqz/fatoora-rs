---
title: Invoice Validation API Reference
description: Validate ZATCA invoice XML with fatoority. Reference for schema checks, local validation options, report fields, stage coverage, errors, and language-specific return values.
---

# Invoice validation

Validate the original invoice XML before relying on its structure or business-rule results. Choose a schema check for UBL structure, or a local ZATCA report for schema, business rules, and applicable integrity checks. For a runnable example, see the [validation guide](../guides/validation.md).

<span id="construction-parsing-and-validation"></span>
## Choose the check

| Operation | What it establishes |
| --- | --- |
| Build an invoice | Implemented field, range, and amount checks; calculated totals. |
| Parse invoice XML | Supported fields and supplied amounts can be represented by the invoice model. |
| Validate the schema | Conformance to the bundled UBL 2.1 schema. |
| Run local ZATCA validation | Results and coverage for the local profile's schema, business rules, signature, QR, and predecessor checks. |
| Sign an invoice | Signature material was generated; no implicit business-rule validation. |
| Parse a signed invoice | Signature material was extracted; no implicit authenticity check. |

No local result proves remote acceptance, certificate issuer trust, or revocation status. Integrity checks verify supported algorithms and references, bind the embedded key to the signature, and compare QR data with the invoice and certificate.

<span id="behavior"></span>
## Inputs and options

All checks take complete invoice XML text and a configuration object. Pass original XML, not Base64 or a file path. Schema checks use bundled resources and do not need network access. Malformed XML is rejected rather than repaired.

Local validation additionally accepts these optional context values:

| Option | Expected value | If omitted |
| --- | --- | --- |
| `previous_invoice_hash` | Canonical Base64 SHA-256 digest, or the SDK's Base64-encoded hexadecimal digest representation. This is the expected predecessor hash, compared with the invoice's PIH. | Predecessor stage reports `context_required`; the report is incomplete and `is_valid` is false. |
| `evaluated_at` | RFC3339 instant with timezone, such as `2026-10-15T09:30:00Z` or `2026-10-15T12:30:00+03:00`. | One clock snapshot is used for the validation run. |

The validator cannot obtain invoice history. Supply predecessor context from your own invoice sequence. An empty string is not an omitted option. APIs that accept options as JSON require an object containing only these keys, with string or null values. The encoded options input is limited to **4 KiB (4096 bytes)**; unknown keys and malformed values are rejected.

<span id="local-zatca-report"></span>
## Local ZATCA report

A completed function call means a report was produced. Always inspect `is_valid`; rejected invoices and incomplete coverage can both be returned without an execution error.

| Report field | Value and meaning |
| --- | --- |
| `schema_version` | Report format version, currently `1`. |
| `profile` | Local validation profile identifier, currently `zatca-sdk-238-R3.4.8`. |
| `evaluated_at` | The evaluation clock snapshot, including offset. |
| `stages` | Ordered stage results: `xsd`, `cen`, `ksa`, `signature`, `qr`, `previous_invoice_hash`. |
| `is_complete` | All required stages completed exactly once; explicitly inapplicable signature/QR stages count as covered. |
| `has_errors` | At least one error finding exists, including findings from partial stages. |
| `is_valid` | Complete coverage with no error findings. Warnings do not make this false. |

Each stage contains `stage`, `status`, `findings`, `evaluated_assertions` (the assertion sites evaluated), and optional `provenance` with source `stylesheet` and `sha256`. Provenance identifies the rules used; applications can retain it alongside reports for traceability.

| Stage | Checks |
| --- | --- |
| `xsd` | Bundled UBL XML structure. |
| `cen` | Applicable European invoice business rules in the selected profile. |
| `ksa` | Applicable Saudi invoice business rules in the selected profile. |
| `signature` | Local signature integrity; skipped as inapplicable for standard invoices under this profile. |
| `qr` | QR integrity and consistency; skipped as inapplicable for standard invoices under this profile. |
| `previous_invoice_hash` | Invoice PIH compared with supplied predecessor context. |

| Stage status | Meaning |
| --- | --- |
| `completed` | Checks finished; findings may still contain errors. |
| `not_run` | A dependency failed or execution stopped earlier. |
| `not_applicable` | The selected profile does not require this stage for this invoice. |
| `context_required` | Required predecessor context was not supplied. |
| `evaluation_failed` | Execution stopped before completion; findings may be partial. |

Schema rejection returns a report and skips dependent stages. A report with no findings is not sufficient by itself: it can be incomplete. For example, missing predecessor context can yield `has_errors: false`, `is_complete: false`, and `is_valid: false`.

## Findings

| Finding field | Meaning |
| --- | --- |
| `layer` | `field_checks`, `xsd`, `business_rules`, `signature`, `qr`, or `previous_invoice_hash`. |
| `code` | Stable rule or library identifier; use this for programmatic handling. |
| `severity` | `warning` or `error`. |
| `message` | Human-readable explanation. Wording is not a stable API. |
| `location` | Optional model field path, XPath, or XML source coordinates. |
| `assertion_site` | Optional source assertion identifier on local ZATCA findings. |

Field paths use zero-based indexes, such as `line_items[0].quantity`. XML line and column positions are one-based. Business-rule findings use XPath locations against the original document; some findings have no reliable location.

Field codes include `FIELD_REQUIRED`, `FIELD_EMPTY`, `FIELD_INVALID_FORMAT`, `FIELD_OUT_OF_RANGE`, and `FIELD_MISMATCH`. Schema violations use `XSD_INVALID`. Business-rule findings use their implemented rule codes.

## Execution failures and partial results

An invalid invoice is different from a check that could not finish. Malformed XML, unsupported DTDs, capacity limits, invalid context, and rule/integrity execution failures produce an error. When validation has started, the error carries the partial report and all findings collected so far.

Execution details include `kind`, optional `stage`, `assertion_site`, `location`, and `report`. The error message is exposed directly or in `diagnostics`, depending on the language API. Failure kinds are `invalid_xml`, `unsupported_xml`, `capacity_exceeded`, `invalid_context`, `rule_evaluation`, `schema`, and `integrity`. Invalid options rejected before validation starts need not carry a report. Never treat partial findings as complete coverage. See [errors](errors.md#local-zatca-execution-failures) for the shared error contract.

<span id="validate_xml_invoice_from_str"></span>
<span id="validate"></span>
<span id="validation-reports-rust"></span>
## Language reference

=== "Rust"

    Import these functions and report types from `fatoora_core::invoice::validation`, and `Config` from `fatoora_core::config`.

    **Schema validation**

    ```rust
    validate_xml_invoice_from_str(xml: &str, config: &Config)
        -> Result<(), XmlValidationError>
    validate_xml_invoice_report_from_str(xml: &str, config: &Config)
        -> Result<ValidationReport, XmlValidationError>
    ```

    The first returns `Ok(())` on schema success and `Err` for violations or execution failures. The report form returns `Ok(report)` even for schema violations; inspect `report.has_errors()`. Malformed XML and schema setup failures return `Err` because validation did not complete.

    `ValidationReport` contains `layers_checked: Vec<ValidationLayer>` and `issues: Vec<ValidationFinding>`. The schema report marks only `ValidationLayer::Xsd`, including when schema errors were found. An absent layer makes no claim. Convert builder errors using `ValidationReport::from(&validation_error)` or `ValidationFinding::from(&validation_issue)`; conversion preserves findings but runs no new checks.

    **Local ZATCA validation**

    ```rust
    validate_zatca_invoice_from_str(
        xml: &str,
        config: &Config,
        options: &ZatcaValidationOptions,
    ) -> Result<ZatcaValidationReport, ZatcaValidationError>
    ```

    `ZatcaValidationOptions` has `previous_invoice_hash: Option<String>` and `evaluated_at: Option<chrono::DateTime<chrono::FixedOffset>>`. `Default::default()` omits both. Native callers may omit evaluation time; direct WASM callers must supply it. The 4 KiB JSON limit applies to JSON binding inputs, not this typed options struct.

    `ZatcaValidationReport` exposes `schema_version`, `profile`, `evaluated_at`, and `stages`. Call `is_complete()`, `has_errors()`, and `is_valid()` for derived outcomes. `validation_report()` aggregates findings into the shared report; only completed stages contribute checked layers, and both CEN and KSA must complete before `BusinessRules` is listed. Partial findings remain in the aggregate.

    On `Err(error)`, `error.report` contains the partial `Box<ZatcaValidationReport>`; `error.kind`, `stage`, `assertion_site`, `location`, and `message` describe the failure. Serializing reports includes derived outcomes; deserialization recomputes them from stage coverage. Calls borrow configuration and inputs and do not consume invoice objects.

=== "Python"

    Import from `fatoora`.

    ```python
    validate_xml_invoice_from_str(config: Config, xml: str) -> bool
    validate_zatca_invoice_from_str(
        config: Config,
        xml: str,
        *,
        previous_invoice_hash: str | None = None,
        evaluated_at: str | None = None,
    ) -> dict
    ```

    The schema function returns `True` on success; violations raise an exception rather than returning `False`. Local validation returns a dictionary even when the document is rejected or coverage is incomplete. Inspect `report["is_valid"]` and then `report["stages"]` for explanations.

    The wrapper encodes context as JSON, subject to the 4096-byte options limit. XML and context must be strings (or `None` for absent options); interior NUL characters are rejected. Execution failures raise `FatooraError`; after validation starts, `error.details["report"]` contains partial results. Check whether the key exists because invalid input can fail before a report exists. Configuration is borrowed and remains reusable.

=== "JavaScript"

    Import `Xml` from `fatoority`.

    ```javascript
    const schemaValid = Xml.validate(config, xml);
    const reportJson = Xml.validateZatca(config, xml, JSON.stringify({
      previous_invoice_hash: previousHash,
      evaluated_at: "2026-10-15T09:30:00Z"
    }));
    const report = JSON.parse(reportJson);
    ```

    `Xml.validate(config, xml)` accepts `Config` and XML string, returns `true` on schema success, and throws an `Error` with a `BindingError` cause on violations or execution failures; it does not return `false` for invalid XML.

    `Xml.validateZatca(config, xml, optionsJson = null)` returns a JSON **string**, not a parsed object or Promise. Pass `null` to omit options. The public wrapper supplies one host clock snapshot when `evaluated_at` is omitted. Options are restricted to 4096 UTF-8 bytes. Parse the result, then inspect `report.is_valid`; successful invocation alone is not validation success.

    On execution failure, parse `error.cause.detailsJson()` for structured details and an optional `report`. Invalid options can fail before a report exists. Inputs and configuration remain available; validation does not consume them.

=== "C#"

    Use `Fatoora.Xml`.

    ```csharp
    bool Xml.Validate(Config config, string xml)
    string Xml.ValidateZatca(Config config, string xml, string? optionsJson)
    ```

    `Validate` returns `true` on schema success and throws on violations or execution failures. `ValidateZatca` returns JSON text even for a rejected or incomplete invoice. Pass `null` for default options or a JSON object string with the keys documented above (maximum 4096 UTF-8 bytes). Parse the result with `System.Text.Json` and inspect `is_valid`.

    Both methods borrow configuration, which remains reusable. On `BindingErrorException`, `error.Inner.DetailsJson()` returns structured JSON; a failure after validation starts includes `report`. Dispose the owned `error.Inner` after reading it. Earlier input rejection may omit the report. Use `using` for configuration ownership.

=== "Kotlin"

    Import `com.fatoora.Xml` and `com.fatoora.Config`.

    ```kotlin
    Xml.validate(config: Config, xml: String): Boolean
    Xml.validateZatca(config: Config, xml: String, optionsJson: String? = null): String
    ```

    `validate` returns `true` on schema success; violations and execution failures throw `BindingException`. `validateZatca` returns JSON text for completed calls, including rejected or incomplete invoices. Parse it with your JSON library and inspect `is_valid`.

    Omit `optionsJson` or pass null for defaults; otherwise provide a JSON object string containing the documented context keys, limited to 4096 UTF-8 bytes. `BindingException.detailsJson` contains structured failure details and an optional partial `report`. Invalid options can fail before that report exists. Configuration is borrowed and reusable; close it with `use` when finished.

=== "Java"

    Import `com.fatoora.Xml` and `com.fatoora.Config`.

    ```java
    boolean Xml.validate(Config config, String xml)
    String Xml.validateZatca(Config config, String xml)
    String Xml.validateZatca(Config config, String xml, String optionsJson)
    ```

    `validate` returns `true` on schema success and throws `BindingException` on violations or execution failures. `validateZatca` returns a JSON string even if validation rejects the invoice or coverage is incomplete. Parse the result with your JSON library and inspect `is_valid`.

    The two-argument overload uses default options. The third argument accepts null or a JSON object string with the documented context keys, limited to 4096 UTF-8 bytes. On failure, `error.getDetailsJson()` returns structured details with an optional partial `report`; earlier input rejection may omit it. Configuration remains reusable. Use try-with-resources to close it when finished.

=== "C"

    Include `fatoora.h`.

    ```c
    FatooraStatus fatoora_xml_validate(const FatooraConfig *config,
        const char *xml, bool *out, FatooraError **error);
    FatooraStatus fatoora_xml_validate_zatca(const FatooraConfig *config,
        const char *xml, const char *options_json,
        char **out, FatooraError **error);
    ```

    Inputs are NUL-terminated UTF-8 strings. `config` is borrowed and reusable. Schema validation returns `FATOORA_OK` with `*out = true` on success. Violations and execution failures return an error status, not a successful false result; do not read output on failure.

    For local validation, pass `NULL` options for defaults or a JSON object string (at most 4096 bytes). `FATOORA_OK` means the owned JSON report was produced; parse its `is_valid` field before treating validation as successful. Release report text with `fatoora_string_free()`.

    On failure, `fatoora_error_details_json(error)` returns borrowed JSON text with an optional partial `report`. Read or copy it before freeing the error with `fatoora_error_free()`. Invalid options can fail before a report exists. The error status indicates execution failure; a successfully returned report can separately describe invoice rejection.
