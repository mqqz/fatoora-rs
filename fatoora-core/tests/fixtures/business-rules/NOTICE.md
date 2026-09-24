# SDK-derived business-rule evidence

Source: ZATCA Java SDK `238-R3.4.8`, obtained from the official
[Compliance and Enablement Toolbox](https://zatca.gov.sa/en/E-Invoicing/SystemsDevelopers/ComplianceEnablementToolbox/Pages/DownloadSDK.aspx).

`catalog.json` is a structural extraction of the following SDK files, made on
2026-09-23. It retains executable instruction trees, expressions and messages as
review evidence. Extraction changes the representation and removes non-executable
comments and whitespace-only text. It does not modify the rule predicates.

- `Data/Rules/Schematrons/20210819_ZATCA_E-invoice_Validation_Rules.xsl` declares
  Copyright 2021 ZATCA, GNU LGPL v3.
- `Data/Rules/Schematrons/CEN-EN16931-UBL.xsl` describes itself as based on CEN/EN
  16931:2017 and licensed under LGPL v3 through EUPL v1.2 compatibility. Its header
  attributes ownership of the standard to CEN and its members. This records the
  SDK's notice; the exact upstream revision and conversion basis remain unverified.

The original SDK `LICENSE.txt` is copied as `LICENSE-LGPL-3.0.txt`. Its incorporated
GPL text is included as `LICENSE-GPL-3.0.txt`. Imported expressions and messages
retain their upstream terms; they are not relicensed under fatoora-rs's
MIT/Apache-2.0 license. The source hashes in the catalog identify the precise files
used. The extraction code in `scripts/business_rules.py` is project-authored.

`observations.json` extracts findings from the previously captured SDK-parity logs.
`mutations/` contains modified copies of the repository's standard-invoice fixture
and new official SDK validation output, with input changes and evidence hashes
recorded in its manifest. Source attribution for the original corpus remains in
the root `THIRD_PARTY_NOTICES.md`. Capture scripts under `mutations/capture-tools/`
are project-authored tooling snapshots. No SDK JAR or executable is included.

All rule families and the `integrity/` corpus retain the source attribution above.
The coverage ledger maps all 257 assertion sites to native predicates and tests;
integrity manifests retain SDK results alongside declared local policy differences.
