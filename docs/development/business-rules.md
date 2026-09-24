# Local ZATCA validation

The `zatca-sdk-238-R3.4.8` profile implements all 257 assertion sites in the
pinned SDK stylesheets: 105 CEN sites and 152 Saudi sites. Business rules run as
native Rust predicates over the original XML. XSD validation and XML
canonicalization use libxml2. Runtime validation needs neither Java nor the SDK;
reference captures use the unmodified official SDK CLI, with no direct Saxon
integration.

The existing `validate_xml_invoice_from_str` and
`validate_xml_invoice_report_from_str` APIs still check XSD only. Use
`validate_zatca_invoice_from_str` for the full local pipeline.

## Coverage and outcomes

Every report has these six stages:

| Stage | Checks | Completion requirement |
| --- | --- | --- |
| `xsd` | Bundled UBL 2.1 schema | `completed` |
| `cen` | 105 assertion sites from the SDK CEN stylesheet | `completed` |
| `ksa` | 152 assertion sites from the SDK Saudi stylesheet | `completed` |
| `signature` | Invoice and signed-properties digests, signing key and constrained signature structure | `completed`, or `not_applicable` for standard documents |
| `qr` | TLV structure and values bound to the invoice and signing certificate | `completed`, or `not_applicable` for standard documents |
| `previous_invoice_hash` | PIH encoding and equality with caller-supplied predecessor hash | `completed` |

`completed` means execution finished; a completed stage can contain error
findings. The other statuses are `not_run`, `context_required`, and
`evaluation_failed`. Schema rejection stops dependent stages. A signature
rejection leaves QR validation unrun because its verified inputs are unavailable.

`ZatcaValidationReport::is_complete()` requires exactly one entry for each stage
with the status shown above. `has_errors()` includes findings from partial stages.
`is_valid()` requires completion without error findings; warnings are allowed.
JSON reports include all three derived booleans. Deserializing a report recomputes
them from its stages, so supplied booleans cannot establish coverage.

Rule findings retain the assertion site, source severity and original message.
Locations use namespace-independent XPath expressions with sibling positions.
CEN and KSA stages also identify the source stylesheet, its SHA-256 and the
assertion sites evaluated. `validation_report()` aggregates findings into the
shared report type, retaining partial findings. It marks `BusinessRules` checked
only when both profiles completed.

`ZatcaValidationOptions::evaluated_at` supplies a reproducible instant and implicit
timezone. Without it, the validator captures the UTC clock once. For chain
continuity, set `previous_invoice_hash` to the predecessor hash saved in trusted
invoice history.
The value must be canonical base64 containing a 32-byte digest or the SDK's
64-byte hexadecimal digest representation. The comparison is exact. Omitting it
leaves the PIH stage `context_required`, even when the embedded PIH is well formed.
Options JSON rejects unknown fields.

Schema or rule rejections return `Ok(report)`. Execution failures return
`ZatcaValidationError` with the partial report, failure kind and available
stage/assertion/location metadata. See [Errors](../reference/errors.md) for the
binding representation.

## Call the validator

Rust:

```rust
use fatoora_core::config::Config;
use fatoora_core::invoice::validation::{
    ZatcaValidationOptions, validate_zatca_invoice_from_str,
};

fn validate(xml: &str, previous_hash: String) -> Result<bool, Box<dyn std::error::Error>> {
    let options = ZatcaValidationOptions {
        evaluated_at: Some("2026-09-23T12:00:00+03:00".parse()?),
        previous_invoice_hash: Some(previous_hash),
    };
    let report = validate_zatca_invoice_from_str(xml, &Config::default(), &options)?;
    eprintln!("{}", serde_json::to_string_pretty(&report)?);
    Ok(report.is_valid())
}
```

CLI:

```sh
fatoora-rs-cli validate --invoice invoice.xml --profile zatca --format json \
  --evaluated-at '2026-09-23T12:00:00+03:00' \
  --previous-invoice-hash "$PREVIOUS_INVOICE_HASH"
```

The ZATCA profile returns exit 0 for valid input, 2 for rejection, 3 for an
execution failure, and 4 for incomplete coverage without errors. Rejection takes
precedence over incomplete coverage. JSON stdout contains one report or execution
error; CLI file/context failures produce a diagnostic object without an invented
report. Ordinary argument usage errors retain clap's stderr diagnostics and exit 2.
Text output includes profile, stage status and finding locations. The default
`--profile xsd --format text` preserves the existing `OK` output and exit 1 on
failure. ZATCA context flags are rejected with the XSD profile.

Python:

```python
from fatoora import Config, Environment, validate_zatca_invoice_from_str
from fatoora.errors import FatooraError

with Config(Environment.NON_PRODUCTION) as config:
    try:
        report = validate_zatca_invoice_from_str(
            config, xml,
            previous_invoice_hash=previous_hash,
            evaluated_at="2026-09-23T12:00:00+03:00",
        )
        print(report["is_valid"], report["stages"])
    except FatooraError as error:
        print(error.details.get("report"))
```

Python returns a dictionary for rejected or incomplete validation. Execution
failures raise a binding exception. Raw XML and string options reject embedded
NULs before C conversion.

C callers use `fatoora_Xml_validate_zatca` with a live `Config`, a length-delimited
XML view, an optional options JSON view, and a `DiplomatWrite` output. Check
`result.is_ok` before reading the report. On failure, inspect the owned
`BindingError` and destroy it with `fatoora_BindingError_destroy`.

An absent options view selects defaults. Otherwise, pass an object with optional
`evaluated_at` and `previous_invoice_hash` fields. A successful call can return a
rejected or incomplete report; inspect `is_valid` before accepting the invoice.
See the [C ownership example](../reference/bindings/c.md) and the
[local validation contract](https://github.com/mqqz/fatoora-rs/blob/main/fatoora-ffi/tests/zatca_contract.c).

## Integrity scope and recorded policies

Standard invoices, credit notes and debit notes mark signature and QR stages
`not_applicable`, following the pinned SDK profile. Simplified documents run both
checks. Local signature verification establishes content and key integrity.
Issuer trust, certificate revocation and remote ZATCA acceptance require separate
verification. Caller-owned history supplies PIH continuity.

The SDK signs the invoice digest bytes with ECDSA-SHA256, applying a second
SHA-256. It does not sign a generic XMLDSig `SignedInfo` preimage. This validator
checks the declared invoice and SignedProperties digests separately, plus
certificate digest, issuer and serial linkage. A recomputed SignedProperties
digest cannot authenticate a changed `SigningTime`; that timestamp is not an
authenticated signing-time claim under this SDK contract.

These policy IDs describe deliberate compatibility and integrity decisions;
they are separate from finding codes such as `QR_TIMESTAMP` or `QR_VAT`.

| Policy | Behavior |
| --- | --- |
| `SDK-QR-001` | This validator follows the SDK's tag 4 comparison against `PayableAmount` (BT-115). The library's QR generator uses `TaxInclusiveAmount`; payable rounding can make its generated QR fail this SDK profile. |
| `SDK-QR-002` | Tag 3 must contain a complete RFC3339 timestamp; a missing offset is interpreted as UTC. Comparison uses instants. Native validation rejects inconsistent offsets, a different day and malformed suffixes accepted by the recorded SDK CLI runs. |
| `SDK-QR-003` | Tag 5 uses exact XML-decimal equality. Native validation rejects `NaN`, exponent syntax and distinct values that collapse to the same binary float. Captures also show the SDK accepting `16.0` against invoice VAT `15.00`; native validation rejects that mismatch. |
| `LOCAL-INTEGRITY-001` | Signature algorithms, references and structure are restricted to the supported profile. Duplicate IDs, unbound references and malformed TLV data are rejected. This is a constrained invoice verifier; arbitrary XMLDSig transforms are unsupported. |

The integrity corpus contains 40 official-SDK reference cases, including six
signed document variants and mutations of signature, QR and PIH fields. Each
case records its native expectation and any applicable policy ID. Differences
stay visible in the evidence instead of changing the SDK logs or expected output.

## Source inventory and offline evidence

The SDK CEN stylesheet contains 103 distinct rule IDs across 105 assertion sites;
the Saudi stylesheet contains 142 IDs across 152 sites. Rule prefixes do not
identify their source file: the CEN profile includes Saudi rules. Coverage keys
combine source, ordinal and rule ID, preserving repeated IDs.

The files under `fatoora-core/tests/fixtures/business-rules/` include:

- `catalog.json` and `catalog.sha256`: source metadata and ordered executable
  template trees. Empty templates are retained because they can suppress later
  rules. Executable guards are distinct from printed diagnostic expressions.
- `coverage.json`: all 257 sites marked implemented, with implementation and test
  paths. Rust tests require this set to match the evaluator metadata exactly.
- `observations.json`: structured findings linked by hashes to the original
  SDK-parity logs. Those original logs do not establish an implicit timezone.
- Sixteen mutation families containing 408 business-rule cases:

| Family | Cases | Family | Cases |
| --- | ---: | --- | ---: |
| `mutations` | 24 | `identity` | 46 |
| `structural` | 57 | `totals` | 18 |
| `ksa-fields` | 22 | `ksa-buyer` | 34 |
| `ksa-common` | 21 | `vat` | 22 |
| `ksa-adjustments` | 21 | `ksa-exemptions` | 24 |
| `ksa-currency` | 26 | `ksa-dates` | 21 |
| `ksa-date-casts` | 10 | `ksa-prepayment` | 28 |
| `ksa-arithmetic` | 28 | `ksa-arithmetic-guards` | 6 |

Each mutation retains its XML, raw SDK logs and process status. Manifests include
expected findings, independently specified target outcomes, execution intervals,
UTC configuration and resource hashes. Copies of the capture scripts accompany
the evidence. `integrity/` stores the separate 40-case integrity corpus.

```sh
python3 scripts/business_rules.py check
python3 scripts/integrity_validation.py check
python3 -m unittest discover -s scripts/tests -v
cargo test -p fatoora-core --locked --offline --lib invoice::validation
```

Offline checks do not invoke Java or load an installed SDK. They verify fixture
integrity and compare native behavior with recorded evidence. Unit regressions
also cover branch boundaries, duplicate operands and per-node execution.

The SDK may log warning sections at ERROR level and may exit 0 after rejection.
The parser therefore reads section severity and structured stage outcomes.
Unavailable stages remain `not_run`; transform failures are execution failures.
The SDK CLI coalesces some findings: two empty item names yield one SDK `BR-25`
warning but two native occurrences with separate locations. Comparisons use the
SDK-visible projection, while native tests retain occurrence counts and locations.

## Native semantics and limits

The evaluator preserves namespaces and repeated XML elements. Numeric lexical
checks use the original text. Its private `ExactDecimal` supports XML decimal
syntax and XPath rounding within a digit budget. The existing invoice `Decimal`
keeps its 96-bit coefficient and invoice rounding contract. Explicit double
operations and `format-number` have separate tests; these differences affect
monetary boundaries and prepayment arithmetic.

The business-rule limits are fixed for the public profile:

| Resource | Limit |
| --- | ---: |
| XML input | 8 MiB |
| Element nodes | 100,000 |
| Element depth | 128 |
| Retained XML data | 64 MiB |
| Decimal digits | 4,096 |
| Findings | 10,000 |
| Finding data | 8 MiB |

Regex evaluation also bounds input/pattern size, compiled size and backtracking.
At most 128 distinct nonliteral input/pattern pairs are cached per invoice.
Exceeding an evaluation limit returns an execution failure with partial findings.
DTD declarations in invoice input are rejected. Bundled XSD bytes are embedded
and compiled from a private temporary directory, so installed binaries and wheels
do not depend on the build checkout. The trusted XMLDSig schema retains its
internal DTD.

## Capture reference evidence

Define mutations and target expectations before invoking the official SDK:

```sh
python3 scripts/business_rules.py inventory \
  --sdk-root "$FATOORA_HOME" --output /tmp/business-rules-inventory
python3 scripts/business_rules.py capture --family ksa-prepayment \
  --sdk-root "$FATOORA_HOME" --output /tmp/business-rules-candidate
python3 scripts/integrity_validation.py capture \
  --sdk-root "$FATOORA_HOME" --output /tmp/integrity-candidate
```

Capture directories must not already exist. The tools verify source pins, use an
isolated SDK copy and preserve raw output. Captures verify that the installed SDK
remains unchanged. Review mismatches against executable source
and SDK logs before replacing a corpus. Keep the coverage ledger and imported
license notices when refreshing source inventories.
