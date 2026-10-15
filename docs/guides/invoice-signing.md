---
title: Sign ZATCA Invoice XML
description: Sign invoice XML with fatoority using a matching certificate and private key. Save the signed invoice and continue with local validation.
---

# Sign ZATCA invoice XML

Sign an invoice using a certificate and its matching private key, then save the
result as `signed.xml`. Signing generates signature material; run validation
separately to check the invoice's local rule and integrity results.

## Prepare the inputs

For a local practice run, save these files in one folder:

- [invoice.xml](../assets/examples/invoice.xml), an unsigned simplified invoice.
- [certificate.pem](../assets/examples/certificate.pem), a demonstration certificate.
- [private-key.pem](../assets/examples/private-key.pem), its matching demonstration key.

These are public test fixtures, suitable only for local examples. For your integration,
use your own invoice and the certificate issued for the private key created during
[CSR generation](csr.md). See [API onboarding](api.md#obtain-credentials) for the next steps.
Do not pair a newly generated key with an unrelated certificate.

The examples write `signed.xml` in your working folder, replacing that file if it exists.

## Run the example

Choose your language, then follow its setup and run instructions.

=== "Rust"
    Install [Rust and Cargo](https://www.rust-lang.org/tools/install), then create a project:

    ```sh
    cargo new fatoority-guide
    cd fatoority-guide
    cargo add fatoora-core
    ```


    Save the code below as `src/main.rs`. Put the input files in the project root and run:

    ```sh
    cargo run
    ```

    [Download this example](../assets/examples/rust/signing.rs).

    ```rust
    --8<-- "docs/assets/examples/rust/signing.rs"
    ```


=== "Python"
    Install the package in your Python environment:

    ```sh
    pip install fatoority
    ```

    Save the code as `signing.py` beside the input files, then run:

    ```sh
    python signing.py
    ```

    [Download this example](../assets/examples/python/signing.py).
    See [Python setup](../reference/bindings/python.md) for package details.

    ```python
    --8<-- "docs/assets/examples/python/signing.py"
    ```


=== "JavaScript"
    Use Node.js 22 or later. In a new working folder, install the package:

    ```sh
    npm install fatoority
    ```

    Save the code as `signing.mjs` beside the input files, then run:

    ```sh
    node signing.mjs
    ```

    [Download this example](../assets/examples/javascript/signing.mjs).
    These examples run in Node.js and can also be adapted to TypeScript. In a browser,
    replace filesystem reads with your application's file input and configure the WASM
    asset as described in the [browser setup](../reference/bindings/javascript.md).
    Keep objects in the WASM instance that created them; do not pass them between workers.

    ```js
    --8<-- "docs/assets/examples/javascript/signing.mjs"
    ```


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

    [Download this example](../assets/examples/csharp/signing.cs).
    The `using` declarations release native objects. Check the
    [supported .NET platforms](../reference/bindings/csharp.md) before deployment.

    ```csharp
    --8<-- "docs/assets/examples/csharp/signing.cs"
    ```


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

    [Download this example](../assets/examples/kotlin/signing.kt).
    `use` releases each native object. For an existing project, or Android's separate
    artifact and file handling, follow [Kotlin setup](../reference/bindings/kotlin.md).
    The binding also supports Maven; its dependency coordinates are listed there.

    ```kotlin
    --8<-- "docs/assets/examples/kotlin/signing.kt"
    ```


=== "Java"
    Use JDK 17+ and Maven for this walkthrough. In an empty project folder,
    save this [pom.xml](../assets/examples/java/pom.xml). It includes the library,
    a JSON parser for the validation example, and the plugin used by the run command.

    Save the code as `src/main/java/Guide.java` (create the folders first).
    Put the input files beside `pom.xml`, then run:

    ```sh
    mvn compile exec:java
    ```

    [Download this example](../assets/examples/java/signing.java).
    Try-with-resources releases native objects. The library itself supports Java 8+;
    see [Java setup](../reference/bindings/kotlin.md) for platform prerequisites,
    Gradle installation, and Android configuration.

    ```java
    --8<-- "docs/assets/examples/java/signing.java"
    ```


=== "C"
    Download and extract the `fatoora-ffi-*` archive for your platform from
    [GitHub Releases](https://github.com/mqqz/fatoority/releases).
    Save the example as `signing.c` in the extracted folder, beside the input files.

    On Linux, compile the example and the supplied adapter, then run:

    ```sh
    cc -std=c11 -Iinclude signing.c src/fatoora.c -L. -lfatoora_ffi -Wl,-rpath,'$ORIGIN' -o signing
    ./signing invoice.xml certificate.pem private-key.pem > signed.xml
    ```

    [Download this example](../assets/examples/c/signing.c).
    For other platforms, follow the [C build instructions](../development/c-api.md#build-and-run).
    The cleanup section releases handles and returned strings, including on failure.



    ```c
    --8<-- "docs/assets/examples/c/signing.c"
    ```


=== "CLI"
    Install the command-line tool with `cargo install fatoora-cli`, or extract a
    [release binary](https://github.com/mqqz/fatoority/releases) and add it to your `PATH`.
    See the [CLI guide](cli.md) for platform setup. Run beside your input files:

    ```sh
    fatoora sign --invoice invoice.xml --cert certificate.pem --key private-key.pem --signed-invoice signed.xml
    ```


## Check the result

Open `signed.xml`. It should contain invoice XML with signature material and QR data.
The examples save the full XML rather than just a hash or signature string.
Keep the resulting document intact when storing or submitting it.

Signing alone does not establish business-rule compliance or gateway acceptance.
Next, [validate the original signed XML](validation.md) before
[reporting or clearance](api.md).

## If something goes wrong

| Symptom | What to check |
| --- | --- |
| Certificate/key parsing fails | Match the input format shown in the selected example; PEM and DER are different representations. |
| Certificate/key mismatch | Use the private key corresponding to the certificate, not a key from a later CSR attempt. |
| XML cannot be parsed | Check that you supplied a supported invoice document, with its required fields and amounts. |
| Signed XML fails local validation | Inspect individual findings; adding a signature does not repair invoice data. |

See the [signing reference](../reference/invoice-signing.md) for signature metadata,
formats, and lower-level operations.
