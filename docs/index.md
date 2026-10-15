---
title: ZATCA E-Invoicing SDK and CLI
description: Build Saudi e-invoicing integrations with fatoority. Sign invoices, validate XML, generate QR payloads, and connect to ZATCA APIs.
---

# ZATCA e-invoicing for your application

fatoority is an open-source toolkit for developers building e-invoicing integrations
in Saudi Arabia. Sign invoice XML, validate it locally, generate QR payloads, and
connect to ZATCA APIs for Phase 1 and Phase 2 workflows.

Use the Rust library, add it to your application in Python, JavaScript/TypeScript,
C#, Kotlin/Java (including Android), or C/C++, or run the command-line tool from your terminal.

[Try it](#try-it-validate-an-invoice){ .md-button .md-button--primary }
[Choose your language](#choose-your-language){ .md-button }
[View on GitHub](https://github.com/mqqz/fatoority)
{ .home-actions }

fatoority is an independent project and is not affiliated with ZATCA.

## What you can build

| Task | How fatoority helps |
| --- | --- |
| [Create and sign invoices](guides/invoice-signing.md) | Build invoice data and sign XML for standard and simplified invoices, credit notes, and debit notes. |
| [Validate invoice XML](guides/validation.md) | Check UBL schemas, local ZATCA business rules, and applicable signature and QR checks before submission. |
| [Generate QR payloads](guides/qr.md) | Generate base64-encoded invoice QR data or read the payload embedded in signed XML. |
| [Generate a certificate signing request](guides/csr.md) | Create a signing key and CSR for device onboarding. |
| [Hash invoices](reference/invoice-signing.md) | Compute invoice hashes and prepare invoice request payloads for API submission. |
| [Connect to ZATCA](guides/api.md) | Integrate onboarding, compliance checks, reporting, and clearance into your application. |

Local validation helps catch problems before submission. It does not establish
ZATCA gateway acceptance or certificate issuer trust. See the
[validation guide](guides/validation.md) for coverage and how to interpret results.

## Try it: validate an invoice

Start with a local XML schema check. You do not need an account, certificate, or
API credentials for this example.

### 1. Install the CLI

With [Rust and Cargo](https://www.rust-lang.org/tools/install) installed, run:

```sh
cargo install fatoora-cli
```

You can also download a binary for your platform from
[GitHub Releases](https://github.com/mqqz/fatoority/releases). Extract the archive
and put the `fatoora` executable on your `PATH`.

### 2. Download the sample invoice

Save [sample-invoice.xml](assets/examples/sample-invoice.xml) in your working
folder. It contains demonstration data for this schema check.

### 3. Run the check

From the folder containing the file:

```sh
fatoora validate --invoice sample-invoice.xml
```

Expected output:

```text
OK
```

`OK` means the XML passes the bundled UBL schema check. To run local ZATCA rules
and inspect individual findings, follow the [invoice validation guide](guides/validation.md).
For more terminal commands, see the [CLI guide](guides/cli.md).

## Choose your language

Install the package for your application, then follow its examples. The project
and most packages are named `fatoority`; existing API names such as Python's
`fatoora` import and Rust's `fatoora_core` remain unchanged.

=== "Rust"
    ```sh
    cargo add fatoora-core
    ```

    Import `fatoora_core` in your code.
    [Start with invoice signing](guides/invoice-signing.md) or browse the
    [Rust API reference](https://docs.rs/fatoora-core/latest/fatoora_core/).

=== "Python"
    ```sh
    pip install fatoority
    ```

    Import `fatoora` in your code.
    [Follow the Python setup and examples](reference/bindings/python.md).

=== "JavaScript"
    ```sh
    npm install fatoority
    ```

    Use the WebAssembly package in Node.js or a browser.
    [Follow the JavaScript/TypeScript setup and examples](reference/bindings/javascript.md),
    including browser asset setup and API transport requirements.

=== "C#"
    ```sh
    dotnet add package Fatoority
    ```

    Use the `Fatoora` namespace with .NET 8 or later.
    [Follow the C# setup and examples](reference/bindings/csharp.md), including
    supported native platforms.

=== "Kotlin / Java / Android"
    Install from Maven Central with Gradle or Maven.

    **Gradle** (`build.gradle.kts`):

    ```kotlin
    repositories { mavenCentral() }
    dependencies {
        implementation("com.fatoority:fatoority:0.4.3")
    }
    ```

    **Maven** (add inside `<dependencies>` in `pom.xml`):

    ```xml
    <dependency>
      <groupId>com.fatoority</groupId>
      <artifactId>fatoority</artifactId>
      <version>0.4.3</version>
    </dependency>
    ```

    Import `com.fatoora` in your code.
    [Follow the Kotlin/Java examples](reference/bindings/kotlin.md) for
    supported platforms and Android setup. For Android, use
    `com.fatoority:fatoority-android:0.4.3` instead of the desktop artifact.

=== "C / C++"
    Download the `fatoora-ffi-*` archive with the native library and C/C++ headers from
    [GitHub Releases](https://github.com/mqqz/fatoority/releases).

    [Follow the C/C++ setup and examples](reference/bindings/c.md) for compilation
    and linking instructions.

## Continue your integration

If you are adding invoicing to an application, start with
[building and signing an invoice](guides/invoice-signing.md), then
[validate the XML](guides/validation.md) before sending it.

For device onboarding, [generate a CSR](guides/csr.md), then use the
[ZATCA API client](guides/api.md) to request credentials and submit invoices.
The guides explain the inputs needed at each step.

## About the project

The core is written in Rust and shared by the CLI and language bindings.
The project code is available under the
[MIT or Apache-2.0 license](https://github.com/mqqz/fatoority#license).
Third-party materials retain their upstream terms; see the
[third-party notices](https://github.com/mqqz/fatoority/blob/main/THIRD_PARTY_NOTICES.md).

See the [SDK compatibility notes](development/sdk-parity.md) for the scope of
comparison with the official SDK, and [benchmarks](benchmarks.md) for measured
performance and methodology.

Need help with an integration? [Open an issue](https://github.com/mqqz/fatoority/issues).
To help improve the library or these docs, read the [contributing guide](contributing.md).
