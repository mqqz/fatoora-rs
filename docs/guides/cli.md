---
title: ZATCA E-Invoicing CLI - Install and Use fatoority
description: Install the fatoora CLI, validate a sample invoice, generate a CSR, sign XML, and read QR payloads. Understand command output and validation exit codes.
---

# Use the fatoora command-line tool

Run invoice tasks from your terminal without writing an application. This guide
starts with a local schema check, then shows CSR generation, signing, and QR
operations. The executable is named `fatoora`; the installable crate is `fatoora-cli`.

## Install and check the command

Choose one installation method:

- With [Rust and Cargo](https://www.rust-lang.org/tools/install), run `cargo install fatoora-cli`.
- Download the `fatoora-cli-*` archive for your platform from
  [GitHub Releases](https://github.com/mqqz/fatoority/releases). Extract it and add
  the folder containing `fatoora` (or `fatoora.exe`) to your `PATH`.

Release archives use `.tar.gz` on Linux/macOS and `.zip` on Windows. They include
license texts and rule notices under `licenses/zatca/`.

Open a terminal and check the installation:

```sh
fatoora --help
```

You should see the command list. Use `fatoora <command> --help` for that command's
options, for example `fatoora sign --help`.

## Validate your first invoice

Save [sample-invoice.xml](../assets/examples/sample-invoice.xml) in your working
folder, open a terminal there, and run:

```sh
fatoora validate --invoice sample-invoice.xml
```

Expected output:

```text
OK
```

This checks the bundled UBL schema locally. It does not run the full ZATCA profile
or submit the invoice. No account or credentials are needed.

## Run local ZATCA checks

For a practice report, download [invoice.xml](../assets/examples/invoice.xml) and
[previous-hash.txt](../assets/examples/previous-hash.txt). This unsigned sample
passes the schema check but can produce signature and QR findings under the full
profile. The predecessor file is context for this sample only.

=== "Linux / macOS shell"
    ```sh
    fatoora validate --invoice invoice.xml --profile zatca --format json \
      --previous-invoice-hash "$(cat previous-hash.txt)"
    ```

=== "PowerShell"
    ```powershell
    fatoora validate --invoice invoice.xml --profile zatca --format json `
      --previous-invoice-hash (Get-Content -Raw previous-hash.txt).Trim()
    ```

For real invoices, obtain the predecessor hash from trusted invoice history. Read
`is_valid`, `is_complete`, and the stage findings in the JSON output. A complete
local check still does not establish gateway acceptance or certificate issuer trust.
See [invoice validation](validation.md) for interpreting the report.

Use `--evaluated-at` with an RFC3339 timestamp only when you need a fixed evaluation
time, such as a reproducible historical test. Otherwise the command uses the current clock.

## Generate a CSR and private key

Download [csr.properties](../assets/examples/csr.properties) for a non-production
practice run, then run:

```sh
fatoora csr --csr-config csr.properties --generated-csr csr.pem --private-key key.pem --pem
```

This writes `csr.pem` and `key.pem`. Keep the key private. Before onboarding your
own device, replace the sample properties using the [CSR guide](csr.md).

`--pem` selects PEM text; without it, output is base64 DER. Without output-file
options, the command writes the CSR and key to standard output.

## Sign invoice XML

For a local example, download [invoice.xml](../assets/examples/invoice.xml),
[certificate.pem](../assets/examples/certificate.pem), and
[private-key.pem](../assets/examples/private-key.pem). The certificate and key are
public demonstration fixtures, not credentials for your business.

```sh
fatoora sign --invoice invoice.xml --cert certificate.pem --key private-key.pem --signed-invoice signed.xml
```

The command writes `signed.xml`. Use your own matching certificate and key in an
integration. The [signing guide](invoice-signing.md) explains their origin and the
next validation step. Certificate and key formats must match: both PEM, or both
DER with `--cert-format der --key-format der`.

Output-file commands can replace existing files; choose paths appropriate to your workflow.

## Read or generate QR payloads

To read the payload already embedded in `signed.xml`:

```sh
fatoora qr-read --invoice signed.xml
```

To generate a payload from an unsigned invoice:

```sh
fatoora qr --invoice invoice.xml
```

`qr` can also regenerate from signed XML. Add `--fail-on-signed` when your workflow
should reject signed input. Output is base64-encoded text; redirect it to `qr.txt`
if needed. The [QR guide](qr.md) explains how to pass it to an image renderer.

## Compute a hash or prepare a request payload

```sh
fatoora generate-hash --invoice invoice.xml
```

This prints a base64 invoice hash. For signed XML, it prints the signed hash;
otherwise it hashes finalized invoice XML.

```sh
fatoora invoice-request --invoice signed.xml --api-request request.json
```

This writes a request payload to `request.json`. It does not submit it. Continue
with the [API integration guide](api.md) to handle credentials and acceptance.

## Interpret validation exit codes

The default schema command and the ZATCA profile have different exit contracts:

| Mode | Exit code | Meaning |
| --- | --- | --- |
| Schema check | `0` | Schema valid; prints `OK` |
| Schema check | `1` | Validation or execution failure |
| ZATCA profile | `0` | Valid, including complete coverage; warnings can remain |
| ZATCA profile | `2` | Invoice rejected |
| ZATCA profile | `3` | Execution failure; inspect any partial report |
| ZATCA profile | `4` | Incomplete coverage |
| Command usage | `2` | Invalid arguments; read the usage message |

Do not interpret code `2` without considering whether arguments were accepted
and a validation report was produced.

## If something goes wrong

| Symptom | What to check |
| --- | --- |
| Command not found | Extract the release archive, update `PATH`, and open a new terminal. |
| Input file not found | Run from the input folder or use an absolute path. |
| Certificate/key error | Check that the pair matches and both files use the selected format. |
| Incomplete report | Supply trusted predecessor context and inspect missing stages. |

For a full walkthrough of a specific task, continue with
[CSR generation](csr.md), [signing](invoice-signing.md), or [validation](validation.md).
