---
title: Validate ZATCA Invoice XML and Business Rules
description: Check UBL schemas and local ZATCA rules with fatoority. Run validation and interpret errors, warnings, and incomplete reports.
---

# Validate ZATCA invoice XML

Check an invoice before submission and inspect the results to decide what needs
fixing. Choose a schema check for XML structure, or the local ZATCA profile for
business rules and applicable integrity checks.

| Check | What it tells you |
| --- | --- |
| UBL schema | Whether the XML conforms to the bundled invoice schema |
| Local ZATCA profile | Business-rule findings, applicable signature/QR checks, and which stages were covered |

Neither check establishes ZATCA gateway acceptance or certificate issuer trust.
Building, parsing, or signing an invoice does not automatically run the full local profile.

## Prepare the inputs

Save [invoice.xml](../assets/examples/invoice.xml) in your working folder.
For the local ZATCA check, also save [previous-hash.txt](../assets/examples/previous-hash.txt).
This file supplies the known predecessor context for this demonstration invoice.
For real invoices, use the previous invoice's hash from your trusted invoice history;
do not copy the current document's claimed predecessor value as independent evidence.

Validate the original XML. Parsing and reserializing it first can change the document
being checked. All schemas are bundled; the check does not contact a gateway.

The sample is unsigned: it is useful for a successful schema check and for exploring
ZATCA findings. Do not expect its full local report to pass signature checks.

## Run the example

Choose your language, then follow its setup and run instructions.

=== "Rust"
    Install [Rust and Cargo](https://www.rust-lang.org/tools/install), then create a project:

    ```sh
    cargo new fatoority-guide
    cd fatoority-guide
    cargo add fatoora-core
    ```

    Also add the JSON serializer used to print the report:

    ```sh
    cargo add serde_json
    ```

    Save the code below as `src/main.rs`. Put the input files in the project root and run:

    ```sh
    cargo run
    ```

    [Download this example](../assets/examples/rust/validation.rs).

    ```rust
    --8<-- "docs/assets/examples/rust/validation.rs"
    ```

    **Run the local ZATCA checks**

    ```sh
    cargo run -- --zatca
    ```

    The example prints the JSON report and exits nonzero when `is_valid` is false.
    Inspect `stages` for the findings rather than treating all failures as execution errors.


=== "Python"
    Install the package in your Python environment:

    ```sh
    pip install fatoority
    ```

    Save the code as `validation.py` beside the input files, then run:

    ```sh
    python validation.py
    ```

    [Download this example](../assets/examples/python/validation.py).
    See [Python setup](../reference/bindings/python.md) for package details.

    ```python
    --8<-- "docs/assets/examples/python/validation.py"
    ```

    **Run the local ZATCA checks**

    ```sh
    python validation.py --zatca
    ```

    The example prints the JSON report and exits nonzero when `is_valid` is false.
    Inspect `stages` for the findings rather than treating all failures as execution errors.


=== "JavaScript"
    Use Node.js 22 or later. In a new working folder, install the package:

    ```sh
    npm install fatoority
    ```

    Save the code as `validation.mjs` beside the input files, then run:

    ```sh
    node validation.mjs
    ```

    [Download this example](../assets/examples/javascript/validation.mjs).
    These examples run in Node.js and can also be adapted to TypeScript. In a browser,
    replace filesystem reads with your application's file input and configure the WASM
    asset as described in the [browser setup](../reference/bindings/javascript.md).
    Keep objects in the WASM instance that created them; do not pass them between workers.

    ```js
    --8<-- "docs/assets/examples/javascript/validation.mjs"
    ```

    **Run the local ZATCA checks**

    ```sh
    node validation.mjs --zatca
    ```

    The example prints the JSON report and exits nonzero when `is_valid` is false.
    Inspect `stages` for the findings rather than treating all failures as execution errors.


=== "C#"
    Use the .NET 8 SDK or later. Create a console application:

    ```sh
    dotnet new console -n FatoorityGuide
    cd FatoorityGuide
    dotnet add package Fatoority
    ```

    Save the code as `Program.cs`. Put the input files beside the project file, then run:

    ```sh
    dotnet run
    ```

    [Download this example](../assets/examples/csharp/validation.cs).
    The `using` declarations release native objects. Check the
    [supported .NET platforms](../reference/bindings/csharp.md) before deployment.

    ```csharp
    --8<-- "docs/assets/examples/csharp/validation.cs"
    ```

    **Run the local ZATCA checks**

    ```sh
    dotnet run -- --zatca
    ```

    The example prints the JSON report and exits nonzero when `is_valid` is false.
    Inspect `stages` for the findings rather than treating all failures as execution errors.


=== "Kotlin"
    For this desktop example, use JDK 17+ and Gradle 8. Create an empty project folder
    and download [build.gradle.kts](../assets/examples/kotlin/build.gradle.kts) and
    [settings.gradle.kts](../assets/examples/kotlin/settings.gradle.kts) into it.
    The build uses Maven Central and includes the JSON library needed by the validation example.

    Save the code as `src/main/kotlin/Main.kt` (create the folders first).
    Put the input files in the project root and run:

    ```sh
    gradle run
    ```

    [Download this example](../assets/examples/kotlin/validation.kt).
    `use` releases each native object. For an existing project, or Android's separate
    artifact and file handling, follow [Kotlin setup](../reference/bindings/kotlin.md).
    The binding also supports Maven; its dependency coordinates are listed there.

    ```kotlin
    --8<-- "docs/assets/examples/kotlin/validation.kt"
    ```

    **Run the local ZATCA checks**

    ```sh
    gradle run --args="--zatca"
    ```

    The example prints the JSON report and exits nonzero when `is_valid` is false.
    Inspect `stages` for the findings rather than treating all failures as execution errors.


=== "Java"
    Use JDK 17+ and Maven for this walkthrough. In an empty project folder,
    save this [pom.xml](../assets/examples/java/pom.xml). It includes the library,
    a JSON parser for the validation example, and the plugin used by the run command.

    Save the code as `src/main/java/Guide.java` (create the folders first).
    Put the input files beside `pom.xml`, then run:

    ```sh
    mvn compile exec:java
    ```

    [Download this example](../assets/examples/java/validation.java).
    Try-with-resources releases native objects. The library itself supports Java 8+;
    see [Java setup](../reference/bindings/kotlin.md) for platform prerequisites,
    Gradle installation, and Android configuration.

    ```java
    --8<-- "docs/assets/examples/java/validation.java"
    ```

    **Run the local ZATCA checks**

    ```sh
    mvn compile exec:java -Dexec.args="--zatca"
    ```

    The example prints the JSON report and exits nonzero when `is_valid` is false.
    Inspect `stages` for the findings rather than treating all failures as execution errors.


=== "C"
    Download and extract the `fatoora-ffi-*` archive for your platform from
    [GitHub Releases](https://github.com/mqqz/fatoority/releases).
    Save the example as `validation.c` in the extracted folder, beside the input files.

    On Linux, compile the example and the supplied adapter, then run:

    ```sh
    cc -std=c11 -Iinclude validation.c src/fatoora.c -L. -lfatoora_ffi -Wl,-rpath,'$ORIGIN' -o validation
    ./validation invoice.xml
    ```

    [Download this example](../assets/examples/c/validation.c).
    For other platforms, follow the [C build instructions](../development/c-api.md#build-and-run).
    The cleanup section releases handles and returned strings, including on failure.

    ```c
    --8<-- "docs/assets/examples/c/validation.c"
    ```

    **Run the local ZATCA checks**

    Save [validation-options.json](../assets/examples/validation-options.json) beside the input.
    It contains predecessor context for the sample only.

    ```sh
    ./validation invoice.xml validation-options.json
    ```

    The example prints the JSON report. Exit 0 here means a report was produced; parse
    `is_valid` and `is_complete` with your application's JSON parser before accepting the invoice.


=== "CLI"
    Install the command-line tool with `cargo install fatoora-cli`, or extract a
    [release binary](https://github.com/mqqz/fatoority/releases) and add it to your `PATH`.
    See the [CLI guide](cli.md) for platform setup. Run beside your input files:

    ```sh
    fatoora validate --invoice invoice.xml
    ```

    For local ZATCA rules, use your shell to pass the predecessor hash. In a POSIX shell:

    ```sh
    fatoora validate --invoice invoice.xml --profile zatca --format json \
      --previous-invoice-hash "$(cat previous-hash.txt)"
    ```

    In PowerShell:

    ```powershell
    fatoora validate --invoice invoice.xml --profile zatca --format json `
      --previous-invoice-hash (Get-Content -Raw previous-hash.txt).Trim()
    ```

    The schema command prints `OK`. The ZATCA command prints a report and returns
    0 for valid, 2 for rejected, 3 for execution failure, or 4 for incomplete coverage.


## Interpret the result

A successful schema check prints a success message. It says nothing about business
rules or gateway acceptance. A local ZATCA check prints a structured report:

| Result | How to use it |
| --- | --- |
| `is_valid: true` | The invoice passes the configured local profile with complete coverage. Keep any warnings. |
| `is_valid: false`, `is_complete: true` | Inspect stage findings and correct the rejected invoice data. |
| `is_complete: false` | Required context or a validation stage is missing. Resolve the gap before treating the invoice as checked. |
| Execution error | The check could not finish normally. Inspect the error and any attached partial report. |

Findings include a stage, code, and message. Warnings alone do not make an otherwise
valid report fail. Do not discard them or reduce every failure to a generic “invalid invoice.”

## Understand the coverage

The local profile implements the pinned SDK `238-R3.4.8` adaptations of CEN and Saudi
rules: 105 CEN assertion sites and 152 Saudi sites. It runs without an external SDK
runtime and uses the same profile in every API environment.

Under this profile, standard invoices skip signature and QR checks. Simplified
invoices check the embedded certificate's key, reference digests, signature, and QR
fields. These establish local integrity, not certificate issuer trust.

The default evaluation time is a single current UTC snapshot. For a reproducible
historical test, supply an explicit evaluation time as documented in the
[validation options](../reference/invoice-validation.md). A fixed demonstration clock
should not become the default for your live integration.

## If something goes wrong

| Symptom | What to check |
| --- | --- |
| Schema rejection | Read the XML/schema error and correct the indicated structure or value. |
| Incomplete predecessor check | Supply the trusted previous-invoice hash from your invoice history. |
| Signature/QR findings on the sample | The downloaded `invoice.xml` is unsigned. To examine signed input, replace it with your signed XML and its matching predecessor context. |
| Different results after editing XML | Run checks on the exact document you plan to submit; edits can invalidate signature material. |

Next, [submit the invoice and check gateway acceptance](api.md).
The [validation reference](../reference/invoice-validation.md) covers report fields
and error contracts; [business-rule development](../development/business-rules.md)
records differences from the SDK.
