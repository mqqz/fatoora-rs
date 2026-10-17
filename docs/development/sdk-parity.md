---
title: ZATCA SDK compatibility and limits
description: Understand fatoority validation coverage, differences from the ZATCA SDK and resource limits before integrating.
---

# SDK compatibility and limits

fatoority uses recorded evidence from ZATCA SDK `238-R3.4.8` to check invoice hashes, canonical XML, signatures, QR data, CSR structure and validation outcomes. Running the library requires neither Java nor an SDK installation.

## What is covered

| Area | Scope |
| --- | --- |
| Invoice formats | Standard and simplified invoices, credit notes and debit notes |
| Signing and hashing | Canonical bytes, invoice digests, signed properties and signature integrity |
| QR | Encoded fields and their relationship to invoice and certificate data |
| CSR | English/Arabic subjects, environments, encoding and signatures |
| Local validation | Bundled UBL schema, 105 CEN assertion sites, 152 Saudi assertion sites and applicable integrity checks |

The [validation reference](../reference/invoice-validation.md) explains report stages and outcomes. The schema-only operation checks XSD; the local ZATCA operation runs the wider pipeline. Signature and QR checks are inapplicable to standard documents under this profile.

Compatibility tests are evidence for the cases they cover. They do not establish certificate issuer trust, revocation status or remote invoice acceptance. Some fixtures intentionally contain rejected invoices; do not treat every fixture as a compliant template.

## Known differences and limitations

| Policy | Behavior |
| --- | --- |
| `SDK-QR-001` | QR generation, signing integrity and SDK-profile validation use `PayableAmount` (BT-115) for tag 4, including prepayment and payable rounding adjustments. This matches the recorded SDK behavior and the [Fatoora Developer Community clarification for SDK 3.3.1 and later](https://zatca1.discourse.group/t/how-to-show-advance-deductions-in-qr-code/890/2). |
| `SDK-QR-002` | Tag 3 must contain a complete RFC3339 timestamp; a missing offset is interpreted as UTC. Comparison uses instants. Native validation rejects inconsistent offsets, a different day and malformed suffixes accepted by the recorded SDK CLI runs. |
| `SDK-QR-003` | Tag 5 uses exact XML-decimal equality. Native validation rejects `NaN`, exponent syntax and distinct values that collapse to the same binary float. Captures also show the SDK accepting `16.0` against invoice VAT `15.00`; native validation rejects that mismatch. |
| `LOCAL-INTEGRITY-001` | Signature algorithms, references and structure are restricted to the supported profile. Duplicate IDs, unbound references and malformed TLV data are rejected. This is a constrained invoice verifier; arbitrary XMLDSig transforms are unsupported. |


The signing contract does not authenticate the signing-time field as a trusted timestamp. Keep that distinction when using signature metadata for audit records.

The recorded foreign-currency builder case fails the SDK rule requiring SAR as VAT accounting currency. Choose invoice currency and tax-accounting behavior according to your integration requirements, and inspect the local validation report before submission.

## Validation resource limits

| Resource | Limit |
| --- | ---: |
| XML input | 8 MiB |
| Element nodes | 100,000 |
| Element depth | 128 |
| Retained XML data | 64 MiB |
| Decimal digits | 4,096 |
| Findings | 10,000 |
| Finding data | 8 MiB |


Exceeding a limit produces an execution error, potentially with a partial report. DTD declarations in invoice input are rejected. Pattern evaluation has additional bounded resource use. See [error details](../reference/errors.md#local-zatca-execution-failures).

## Evidence and maintenance

The frozen manifest retains the historical `SDK-QR-001` mismatch from its capture; it does not describe current QR generation. Current regression tests require both SDK and Rust QR tag 4 to match `PayableAmount`.

The [frozen corpus](https://github.com/mqqz/fatoority/tree/main/fatoora-core/tests/fixtures/sdk-parity) records SDK outputs and checksums. The [recorded verification report](sdk-parity-verification.json) identifies the source and artifacts checked in that run; it is not a verification of every subsequent commit.

Contributors changing these behaviors should follow [validation testing](business-rules.md).
