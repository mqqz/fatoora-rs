---
title: Testing validation and SDK compatibility
description: Run offline validation tests and capture reviewed ZATCA SDK evidence when changing invoice behavior.
---

# Validation and compatibility tests

Use these checks when changing validation, XML serialization, signing, QR generation or CSR encoding. The [compatibility reference](sdk-parity.md) documents user-visible coverage, differences and limits; this page covers maintaining the evidence.

## Run offline checks

From the repository root:

```sh
python3 scripts/business_rules.py check
python3 scripts/integrity_validation.py check
python3 -m unittest discover -s scripts/tests -v
cargo test -p fatoora-core --locked --test sdk_parity
cargo test -p fatoora-core --locked --lib sdk_canonical_corpus
cargo test -p fatoora-core --locked --lib invoice::validation
```

These checks replay frozen evidence without Java or an installed SDK. Cargo may download missing dependencies; add `--offline` when dependencies are cached. Missing fixtures, changed checksums and unexpected results fail the checks.

## Add a regression

Define the expected outcome before changing the implementation. Keep a small failing input and test the result, error or report stage that matters. For a business-rule change, retain the assertion site and location as well as the rule code.

| Fixture directory under `fatoora-core/tests/fixtures/` | Purpose |
| --- | --- |
| `sdk-parity/` | Frozen signing, hashing, QR, schema and CSR evidence |
| `sdk-parity-typed/` | Reviewed captures for changed typed-builder output |
| `business-rules/` | Rule catalog, coverage ledger and SDK observations |

Do not regenerate expected output just to make a failing test pass. Inspect the input, executable rule source and original SDK output. Keep intentional compatibility differences explicit. SDK exit status alone is insufficient: a rejected invoice can still produce exit code zero.

For arithmetic changes, retain independently calculated expectations and exercise rounding boundaries. For integrity changes, include tampered inputs and check that rejection is attributed to the expected stage.

## Compare fresh output with the SDK

This optional step requires the pinned SDK `238-R3.4.8`, its dummy test credentials and a JDK with `java` and `javac`. Set `FATOORA_HOME` to the SDK installation. The tools check the SDK pin and use an isolated copy.

```sh
python3 scripts/sdk_parity.py verify \
  --sdk-root "$FATOORA_HOME" \
  --output /tmp/fatoora-sdk-verification
```

The output directory must not exist. Review `report.json` and its evidence directory. This checks freshly generated output against the recorded layer outcomes; it does not make live gateway requests.

## Refresh evidence intentionally

For unchanged input cases, capture a candidate:

```sh
python3 scripts/sdk_parity.py capture \
  --sdk-root "$FATOORA_HOME" \
  --output /tmp/fatoora-sdk-candidate
```

For an intentional serializer or input change, first run `cargo run -p fatoora-core --locked --example sdk_parity_export -- /tmp/fatoora-sdk-inputs`, then pass `--inputs /tmp/fatoora-sdk-inputs` to capture.

Business-rule and integrity changes use their own capture commands:

```sh
python3 scripts/business_rules.py capture --family ksa-prepayment \
  --sdk-root "$FATOORA_HOME" --output /tmp/business-rules-candidate
python3 scripts/integrity_validation.py capture \
  --sdk-root "$FATOORA_HOME" --output /tmp/integrity-candidate
```

Choose the mutation family relevant to the change. Use new output directories, inspect the candidate differences and raw logs, then replace only reviewed fixtures. Preserve manifests, hashes, source notices and the rule-coverage ledger. Run the offline checks again after updating evidence. A new SDK version requires an explicit pin and source review.
