# Business-rule validation development

[Issue #1](https://github.com/mqqz/fatoora-rs/issues/1) is being implemented against
the two rule profiles in ZATCA SDK `238-R3.4.8`. The current implementation provides
the rule catalog, coverage ledger, SDK finding parser, and targeted reference
fixtures. **Native rule evaluation is still pending.** Public invoice validation
continues to check XSD only.

## Check the evidence offline

```sh
python3 scripts/business_rules.py check
python3 -m unittest discover -s scripts/tests -v
```

These commands require Python 3.9+ and use only its standard library. They do not
start Java, read an installed SDK, fetch files, or regenerate expected results.
The check reports the number of implemented and pending assertion sites. A
successful evidence check establishes fixture integrity, not invoice compliance.

The fixtures in `fatoora-core/tests/fixtures/business-rules/` contain:

- `catalog.json` and `catalog.sha256`: both SDK rule sources, their namespaces,
  ordered executable template trees, global declarations, and assertion metadata.
  Extraction preserves zero-assertion templates because they can suppress a later
  rule. The trees preserve the source instructions for review.
- `coverage.json`: one entry per assertion site. All 257 sites initially remain
  pending. An implemented entry needs implementation and test paths. An
  unreachable entry needs evidence. File paths alone do not establish semantic
  coverage; reviewers must check branch and boundary tests.
- `observations.json`: structured findings recovered from the existing SDK-parity
  corpus, with hashes linking every observation to its original process and log
  evidence. The original corpus remains unchanged. Its clock is visible in logs;
  its implicit timezone was not recorded and must not be inferred.
- `mutations/`: 24 captured cases covering monetary discrepancies, decimal scale,
  tax currency, duplicate tax totals, repeated empty item names, namespace aliases,
  character references, and time-rule behavior. Each case includes input XML,
  SDK output, process status, expected findings, and independently written target
  expectations. The manifest records execution intervals, UTC configuration,
  SDK/resource hashes and copies of the capture scripts.

## Interpret SDK findings accurately

The SDK's CEN profile has 105 assertion sites and 103 distinct IDs. Its Saudi
profile has 152 sites and 142 distinct IDs. The source names do not partition rule
prefixes: the CEN file includes Saudi rules. Repeated IDs are separate coverage
entries, identified by source, ordinal, and rule ID.

Executable conditions and diagnostic expressions are separate catalog fields.
For example, SDK CEN `BR-O-08` executes a different condition from the `test`
expression it prints. The catalog retains the actual guards, local variables,
template priority and traversal instructions.

SDK output includes the validation layer, error/warning section, code and message.
It does not expose XML locations. Warning section headings can be logged at ERROR
level; the parser uses the section's severity and keeps the actual message text.
Missing stages remain `not_run`. A zero process exit code can accompany rejected
invoices.

The `repeated-empty-item-name` fixture has two empty line item names but the SDK
prints only one `BR-25` warning. The manifest records both observations: one
SDK-visible warning and two expected native occurrences. Do not infer a general
deduplication algorithm from this example, discard duplicate log entries, or use
SDK finding counts as a substitute for per-node execution tests.

Signed fixtures in the existing corpus establish this observed stage matrix for
SDK `238-R3.4.8`:

| Document types | XSD / CEN / KSA | Signature / QR | PIH |
| --- | --- | --- | --- |
| Standard invoice, credit note, debit note | Run | Not run | Run |
| Simplified invoice, credit note, debit note | Run | Run | Run |

This describes recorded SDK execution. It does not establish certificate trust,
remote acceptance, or continuity with caller-owned invoice history.

## Capture a reviewed candidate

Only the unmodified official SDK's public CLI is used for reference validation.
There is no direct Saxon integration. Normal development and offline CI need
neither tool.

```sh
# Extract source information without executing Java or the SDK.
python3 scripts/business_rules.py inventory \
  --sdk-root "$FATOORA_HOME" --output /tmp/business-rules-inventory

# Validate the defined mutations through the SDK in an isolated temporary copy.
python3 scripts/business_rules.py capture \
  --sdk-root "$FATOORA_HOME" --output /tmp/business-rules-candidate
```

Output directories must not already exist. Capture checks the JAR, both rule
files, existing source fixtures, and dummy credentials against their pins. It
rewrites configuration only in the scratch SDK and verifies that the installed
SDK files did not change, including on failures. It records timezone as UTC and
replaces inherited `JAVA_TOOL_OPTIONS` for that invocation. All diagnostic logs,
including rejected expectation comparisons, are retained for review.

`mutation_cases()` specifies inputs and target expectations before capture.
Capture fails when a target outcome changes, including when a supposedly absent
finding comes from a stage that never ran. Review such a mismatch against the
executable catalog and raw SDK logs before changing an expectation. The recorded
deduplication observation is one such reviewed discrepancy.

After review, replace `mutations/` with the candidate and run the offline checks.
For source-catalog changes, compare the inventory candidate as well; never reset
an existing coverage ledger to the generated all-pending ledger. Keep imported
source attribution and license notices with generated materials.
