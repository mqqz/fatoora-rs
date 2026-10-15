---
title: Generate a ZATCA CSR and Private Key
description: Generate a certificate signing request and private key with fatoority. Prepare CSR properties, choose an environment, and save your onboarding files.
---

# Generate a ZATCA CSR and private key

A certificate signing request (CSR) contains the identity and public key of your
invoicing device. Use it during onboarding to request credentials from ZATCA.
This walkthrough creates a CSR and its matching private key locally.

## Prepare the inputs

Download [csr.properties](../assets/examples/csr.properties) into a working folder.
The sample contains demonstration values and targets the non-production environment.
You can run it unchanged to learn the workflow.

For your own device, replace the sample values:

| Property | What to supply |
| --- | --- |
| `csr.common.name` | Your device or solution common name |
| `csr.serial.number` | The solution serial number in ZATCA's required format |
| `csr.organization.identifier` | Your organization's VAT identifier |
| `csr.organization.unit.name` | The branch or organizational unit |
| `csr.organization.name` | The legal organization name |
| `csr.country.name` | The country code, such as `SA` |
| `csr.invoice.type` | The invoice-type capability code required for your device |
| `csr.location.address` | The business location |
| `csr.industry.business.category` | The business activity |

Use the current field requirements from the
[ZATCA developer portal](https://sandbox.zatca.gov.sa/IntegrationSandbox) when onboarding
a real device. The sample values are not a registration for your business.
Keep the CSR environment consistent with the API environment you will use next.
The examples replace `csr.pem` and `key.pem` if those files already exist.

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

    [Download this example](../assets/examples/rust/csr.rs).

    ```rust
    --8<-- "docs/assets/examples/rust/csr.rs"
    ```


=== "Python"
    Install the package in your Python environment:

    ```sh
    pip install fatoority
    ```

    Save the code as `csr.py` beside the input files, then run:

    ```sh
    python csr.py
    ```

    [Download this example](../assets/examples/python/csr.py).
    See [Python setup](../reference/bindings/python.md) for package details.

    ```python
    --8<-- "docs/assets/examples/python/csr.py"
    ```


=== "JavaScript"
    Use Node.js 22 or later. In a new working folder, install the package:

    ```sh
    npm install fatoority
    ```

    Save the code as `csr.mjs` beside the input files, then run:

    ```sh
    node csr.mjs
    ```

    [Download this example](../assets/examples/javascript/csr.mjs).
    These examples run in Node.js and can also be adapted to TypeScript. In a browser,
    replace filesystem reads with your application's file input and configure the WASM
    asset as described in the [browser setup](../reference/bindings/javascript.md).
    Keep objects in the WASM instance that created them; do not pass them between workers.

    ```js
    --8<-- "docs/assets/examples/javascript/csr.mjs"
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

    [Download this example](../assets/examples/csharp/csr.cs).
    The `using` declarations release native objects. Check the
    [supported .NET platforms](../reference/bindings/csharp.md) before deployment.

    ```csharp
    --8<-- "docs/assets/examples/csharp/csr.cs"
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

    [Download this example](../assets/examples/kotlin/csr.kt).
    `use` releases each native object. For an existing project, or Android's separate
    artifact and file handling, follow [Kotlin setup](../reference/bindings/kotlin.md).
    The binding also supports Maven; its dependency coordinates are listed there.

    ```kotlin
    --8<-- "docs/assets/examples/kotlin/csr.kt"
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

    [Download this example](../assets/examples/java/csr.java).
    Try-with-resources releases native objects. The library itself supports Java 8+;
    see [Java setup](../reference/bindings/kotlin.md) for platform prerequisites,
    Gradle installation, and Android configuration.

    ```java
    --8<-- "docs/assets/examples/java/csr.java"
    ```


=== "C"
    Download and extract the `fatoora-ffi-*` archive for your platform from
    [GitHub Releases](https://github.com/mqqz/fatoority/releases).
    Save the example as `csr.c` in the extracted folder, beside the input files.

    On Linux, compile the example and the supplied adapter, then run:

    ```sh
    cc -std=c11 -Iinclude csr.c src/fatoora.c -L. -lfatoora_ffi -Wl,-rpath,'$ORIGIN' -o csr
    ./csr csr.properties
    ```

    [Download this example](../assets/examples/c/csr.c).
    For other platforms, follow the [C installation and linking reference](../reference/bindings/c.md).
    The cleanup section releases handles and returned strings, including on failure.

    The example saves `key.pem` and `csr.pem`. Keep the key private.


    ```c
    --8<-- "docs/assets/examples/c/csr.c"
    ```


=== "CLI"
    Install the command-line tool with `cargo install fatoora-cli`, or extract a
    [release binary](https://github.com/mqqz/fatoority/releases) and add it to your `PATH`.
    See the [CLI guide](cli.md) for platform setup. Run beside your input files:

    ```sh
    fatoora csr --csr-config csr.properties --generated-csr csr.pem --private-key key.pem --pem
    ```


## Check the result

You should have a CSR beginning with `-----BEGIN CERTIFICATE REQUEST-----` and a
key beginning with `-----BEGIN PRIVATE KEY-----`. The selected example explains
where it writes those blocks. The CSR can be submitted for onboarding; keep the
private key for signing and do not send it as part of the CSR request.

The examples use PEM text. Some integrations expect base64 DER instead; choose
the representation required by the receiving endpoint rather than encoding PEM again.

## If something goes wrong

| Symptom | What to check |
| --- | --- |
| Configuration file not found | Run from the folder containing `csr.properties`, or change the path in your example. |
| Properties cannot be parsed | Check spelling, missing values, and the property names in the table above. |
| Onboarding rejects the request | Check business identifiers, the required device fields, OTP, and environment against the portal response. |

Next, [request credentials and connect to ZATCA](api.md#obtain-credentials).
See the [CSR reference](../reference/csr.md) for additional formats and constructors.
