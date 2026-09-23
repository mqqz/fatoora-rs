# Business-rule validation development

[Issue #1](https://github.com/mqqz/fatoora-rs/issues/1) is being implemented against
the two rule profiles in ZATCA SDK `238-R3.4.8`. An internal Rust evaluator covers
104 of the 257 inventoried assertion sites, with source metadata and offline SDK
comparisons. **The full profile remains incomplete.** Public invoice validation
continues to check XSD only; the native subset has no public entry point.

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
- `coverage.json`: one entry per assertion site, with 104 implemented and 153
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

- `identity/`: 46 official-SDK cases covering seller and buyer identifiers, VAT
  numbers, address presence, Unicode field lengths, scheme whitespace,
  predictable identifiers, and contact fields. Capture them with
  `capture --family identity --output /tmp/business-rule-identity`.

- `structural/`: 57 official-SDK cases covering field presence, lexical limits,
  quantity zero, category presence and the pinned code lists. Capture them with
  `capture --family structural --output /tmp/business-rule-structural`.

- `totals/`: 18 official-SDK cases for allowance, charge, exclusive and payable
  totals, including empty charge totals and double-to-decimal boundaries.
  Capture them with `capture --family totals --output /tmp/business-rule-totals`.

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
SDK-visible warning and two expected native occurrences. Its two empty names
also produce two native `BR-KSA-F-06-C19` findings and one SDK finding. Do not infer a general
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

## Test the internal native subset

```sh
cargo test -p fatoora-core --locked --offline --lib business_rules
```

The module in `fatoora-core/src/invoice/validation/business_rules/` evaluates
`BR-CO-10` through `BR-CO-16`, `BR-25`, the selected total and allowance
decimal limits, `BR-KSA-EN16931-02`/`09`, 20 Saudi identity/address checks, and 60 CEN structure and code-list checks.
Tests compare this subset against all 145 mutation captures and the signed
fixtures for all six document variants.
Additional tests cover locations, duplicate operands, template suppression,
overlapping patterns, and evaluation failures. The Rust metadata test requires
the implemented-site set to match the coverage ledger exactly.

The evaluator reads the original XML without importing it into the invoice
model. It retains namespace identity, repeated elements and numeric text, rejects
DTDs, and bounds input size, depth, nodes, retained data and findings. Locations
are XPath expressions using namespace URIs and sibling positions.

Its private `ExactDecimal` uses arbitrary-precision integers within a configured
digit budget. It accepts XML decimal syntax and implements XPath midpoint
rounding toward positive infinity. The existing invoice `Decimal` retains its
96-bit coefficient, scale limit and invoice rounding contract. Lexical precision
checks use XML text directly. Explicit double conversion and rounding have
separate primitive tests. `BR-CO-13` preserves the source's double sum before
casting its binary value to decimal; other implemented monetary predicates
use explicit decimals.

Reports identify the pinned profile, caller-supplied evaluation instant and
offset, source, completed assertion sites, findings and source status. Successful
runs are marked `evaluated_subset` and cannot claim complete validation. An
execution error retains earlier findings, marks its source `evaluation_failed`,
and leaves subsequent sources `not_run`. Findings have deterministic source,
assertion-site and document order. XSD and cryptographic checks are outside this
internal entry point.
