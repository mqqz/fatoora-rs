# SDK compatibility tests

The required test corpus records observations from ZATCA Java SDK `238-R3.4.8`. Ordinary tests need neither Java nor an SDK installation. They compare hashes, exact canonical bytes, signed XML, decoded QR fields, XSD outcomes, and CSR structures/signatures against frozen evidence.

```sh
python3 -m unittest discover -s scripts/tests -v
cargo test -p fatoora-core --locked --test sdk_parity
cargo test -p fatoora-core --locked --lib sdk_canonical_corpus
```

A missing file, checksum mismatch, removed required case, or missing SDK result fails the suite. Tests never regenerate expected results. CI runs the workspace coverage suite with SDK variables unset and a failing Java executable, and checks that Java was never invoked.

## What the corpus proves

The 53 cases cover all six combinations of standard/simplified invoices, credit notes and debit notes; additional business shapes; XML formatting and namespace variations; malformed/schema-invalid input; and twelve English/Arabic, individual/VAT-group, production/simulation/nonproduction CSR combinations plus two rejected CSR configurations.

Offline tests verify fresh Rust signatures and reference digests, both XML and typed signing paths, QR links to XML/certificate data, and CSR proof of possession. Deliberate changes to signed content, references, signatures, certificates, QR tags, and TLV framing must be rejected by the test verifier.

SDK signature and QR validation are conditional: this release omits those checks for standard invoices. `not_run` means the SDK emitted no marker for that layer; it is never counted as a pass. Independent offline cryptographic checks cover standard and simplified documents.

Rust XML validation currently checks XSD. Recorded SDK EN/KSA/global results are separate observations and do not imply that Rust implements those business rules. Diagnostic text is preserved as evidence; equality assertions use layer outcomes and decoded fields.

Two observations remain visible:

- `SDK-QR-001`, tracked under [issue #2](https://github.com/mqqz/fatoora-rs/issues/2): the SDK's payable-rounding sample/output contains QR tag 4 `1000.00`, while its XML tax-inclusive total is `1000.01`. Rust uses `1000.01`, following the [ZATCA technical guideline's XML mapping](https://www.zatca.gov.sa/en/E-Invoicing/Introduction/Guidelines/Documents/E-invoicing-Detailed-Technical-Guideline.pdf), page 61. The test asserts both exact observations, so a changed or resolved difference fails for review.
- The existing foreign-currency builder case fails SDK KSA rule `BR-KSA-EN16931-02` because its VAT accounting currency is not SAR. SDK-signed and Rust-signed versions produce the same recorded failure. Fixing foreign-currency business-rule generation is separate work; this fixture is not a globally compliant example.

Canonicalization preserves character-content whitespace and namespace prefixes. Cases have individual SDK expectations; only explicitly tested transformations are assumed to preserve a digest. Two small test-only Java adapters call methods in the checksum-pinned SDK to obtain canonical bytes and SignedProperties digest preimages. Capture cross-checks these bytes against public CLI outputs. The adapters are not runtime dependencies or public library APIs.

## Verify current Rust output with the SDK

Use the locally installed dummy test credentials. The tool rejects an unexpected SDK JAR or different credentials before capture. `$FATOORA_HOME` may point to `Apps`; `--sdk-root` also accepts its parent directory.

```sh
python3 scripts/sdk_parity.py verify \
  --sdk-root "$FATOORA_HOME" \
  --output /tmp/fatoora-sdk-verification
```

The output directory must not exist. The command exports fresh Rust XML from both signing paths, validates it with the SDK, and compares every reported layer with the baseline. It also submits a deliberately corrupted signature and requires rejection. Inspect `report.json` and `evidence/<case>/` for exact results. A missing SDK, Java, output artifact, ambiguous marker, timeout, or changed result fails the command.

The tool uses a temporary SDK copy, rewrites absolute configuration paths into it, and compares the installed SDK's file checksums before and after successful execution. Failure evidence remains in the requested output directory. It never overwrites installed keys, certificates, or configuration.

The [recorded verification run](sdk-parity-verification.json) identifies the corpus manifest and Rust source hashes, generated artifact hashes, and each observed layer outcome.

## Refresh the corpus

Capture requires Python 3.9+, a JDK with `java` and `javac` (the baseline used OpenJDK 11.0.25), and SDK `238-R3.4.8`. Normal replay has none of those Java requirements. SDK archive download and installation remain explicit maintainer actions.

To recapture the same frozen builder inputs:

```sh
python3 scripts/sdk_parity.py capture \
  --sdk-root "$FATOORA_HOME" \
  --output /tmp/fatoora-sdk-candidate
```

For an intentional serializer/input change, export a new candidate input set first:

```sh
cargo run -p fatoora-core --locked --example sdk_parity_export -- /tmp/fatoora-sdk-inputs
python3 scripts/sdk_parity.py capture \
  --sdk-root "$FATOORA_HOME" \
  --inputs /tmp/fatoora-sdk-inputs \
  --output /tmp/fatoora-sdk-candidate
```

Review the sibling `fatoora-sdk-candidate-diff.json`, raw evidence, and artifact changes. The semantic report excludes randomized QR signature bytes; the raw artifacts retain them and offline tests verify them cryptographically. CSR random keys/signatures are also compared structurally and cryptographically by Rust tests rather than by the summary report.

Copy reviewed candidate files into `fatoora-core/tests/fixtures/sdk-parity/`, run the offline commands above, then run explicit SDK verification. Review source notices when adding imported material. A changed SDK requires an intentional pin update and adapter review; the capture command never downloads a new SDK or accepts an unknown binary automatically.

`manifest.json` records the SDK/resource hashes, Java version, tool/adapter hashes, capture time, source revision, case inventory, and every artifact checksum. Source revision and tool hashes are separate because capture may run on uncommitted changes. Each operation preserves its exact argv, working directory, exit code, stdout, and stderr. Temporary paths in those records document the original invocation and are not needed for replay.

## Compatibility fixes exposed by the corpus

The suite exposed UTF-8 corruption in Arabic CSR properties, incorrect CSR template ASN.1 encoding and name ordering, acceptance of nonbinary CSR capability flags, an added QR timestamp suffix, and a SignedProperties digest mismatch when re-signing existing formatted XML. The associated changes affect generated artifacts across bindings; no public function signatures changed. The UTF-8 fix makes the already-transitive `encoding_rs` dependency explicit so the existing property parser can use its supported UTF-8 mode.

### Invoice flag regression evidence

The original `cases/` corpus remains frozen. Correcting XML serialization to
preserve invoice flags changed five typed-builder inputs; their SDK captures
live in the sibling `sdk-parity-typed/` corpus. Its separate manifest records
the five case IDs, capture metadata, and hashes for every artifact and capture
tool. The original manifest stays byte-for-byte unchanged because business-rule
and integrity evidence pins its digest.

The SDK rejects the corrected `standard-invoice` and `export-self-billed`
inputs with BR-KSA-07 because both export and self-billing are set. Their old
XML omitted those flags. Tests preserve these rejections as expected outcomes;
the other three refreshed cases retain their previous validation outcomes.
