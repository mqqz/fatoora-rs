---
title: Generate and Read ZATCA QR Payloads
description: Read the QR payload from signed invoice XML with fatoority, generate payloads with the CLI, and prepare encoded text for QR image rendering.
---

# Generate and read ZATCA QR payloads

A ZATCA invoice QR code contains a base64-encoded TLV (tag-length-value) payload.
fatoority exposes that text so you can store it or pass it to a QR image renderer.
This walkthrough reads an existing payload from a signed invoice and saves `qr.txt`.

## Prepare the input

Download [signed.xml](../assets/examples/signed.xml) into a working folder, or use
an invoice you created with the [signing guide](invoice-signing.md).
The download is a public demonstration fixture; reading its QR data does not
verify its signature or establish that it is accepted by ZATCA.

## Choose the operation

Read the embedded payload when you want exactly what an existing signed invoice contains.
When creating a new signed invoice, signing also produces its QR data; sign first,
then read that payload. The command-line example additionally shows how to generate
payloads from unsigned XML.

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

    [Download this example](../assets/examples/rust/qr.rs).

    ```rust
    --8<-- "docs/assets/examples/rust/qr.rs"
    ```


=== "Python"
    Install the package in your Python environment:

    ```sh
    pip install fatoority
    ```

    Save the code as `qr.py` beside the input files, then run:

    ```sh
    python qr.py
    ```

    [Download this example](../assets/examples/python/qr.py).
    See [Python setup](../reference/bindings/python.md) for package details.

    ```python
    --8<-- "docs/assets/examples/python/qr.py"
    ```


=== "JavaScript"
    Use Node.js 22 or later. In a new working folder, install the package:

    ```sh
    npm install fatoority
    ```

    Save the code as `qr.mjs` beside the input files, then run:

    ```sh
    node qr.mjs
    ```

    [Download this example](../assets/examples/javascript/qr.mjs).
    These examples run in Node.js and can also be adapted to TypeScript. In a browser,
    replace filesystem reads with your application's file input and configure the WASM
    asset as described in the [browser setup](../reference/bindings/javascript.md).
    Keep objects in the WASM instance that created them; do not pass them between workers.

    ```js
    --8<-- "docs/assets/examples/javascript/qr.mjs"
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

    [Download this example](../assets/examples/csharp/qr.cs).
    The `using` declarations release native objects. Check the
    [supported .NET platforms](../reference/bindings/csharp.md) before deployment.

    ```csharp
    --8<-- "docs/assets/examples/csharp/qr.cs"
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

    [Download this example](../assets/examples/kotlin/qr.kt).
    `use` releases each native object. For an existing project, or Android's separate
    artifact and file handling, follow [Kotlin setup](../reference/bindings/kotlin.md).
    The binding also supports Maven; its dependency coordinates are listed there.

    ```kotlin
    --8<-- "docs/assets/examples/kotlin/qr.kt"
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

    [Download this example](../assets/examples/java/qr.java).
    Try-with-resources releases native objects. The library itself supports Java 8+;
    see [Java setup](../reference/bindings/kotlin.md) for platform prerequisites,
    Gradle installation, and Android configuration.

    ```java
    --8<-- "docs/assets/examples/java/qr.java"
    ```


=== "C"
    Download and extract the `fatoora-ffi-*` archive for your platform from
    [GitHub Releases](https://github.com/mqqz/fatoority/releases).
    Save the example as `qr.c` in the extracted folder, beside the input files.

    On Linux, compile the example and the supplied adapter, then run:

    ```sh
    cc -std=c11 -Iinclude qr.c src/fatoora.c -L. -lfatoora_ffi -Wl,-rpath,'$ORIGIN' -o qr
    ./qr signed.xml > qr.txt
    ```

    [Download this example](../assets/examples/c/qr.c).
    For other platforms, follow the [C build instructions](../development/c-api.md#build-and-run).
    The cleanup section releases handles and returned strings, including on failure.

    ```c
    --8<-- "docs/assets/examples/c/qr.c"
    ```


=== "CLI"
    Install the command-line tool with `cargo install fatoora-cli`, or extract a
    [release binary](https://github.com/mqqz/fatoority/releases) and add it to your `PATH`.
    See the [CLI guide](cli.md) for platform setup. Run beside your input files:

    ```sh
    fatoora qr-read --invoice signed.xml > qr.txt
    ```

    To generate a payload from an unsigned invoice instead:

    ```sh
    fatoora qr --invoice invoice.xml > qr.txt
    ```

    `qr` generates or regenerates a payload. `qr-read` extracts the payload already
    embedded in signed XML. Add `--fail-on-signed` to `qr` if your workflow should
    reject signed input. These commands write encoded text, not an image.


## Check the result

The example writes `qr.txt`, containing the base64-encoded payload. It is text,
not a PNG or SVG. Tags 1–5 carry seller and amount data; signing tags are present
when supplied by the invoice. The encoded payload must fit the supported size limit.

## Render a QR image

Read the payload from `qr.txt`, removing any trailing line break from terminal
output. Pass that base64 text directly to your application's QR rendering library.
Do not base64-encode the text again. Select the image size
and output format for your receipt or invoice layout, then scan the rendered image
to confirm it decodes to the same payload.

Image rendering is a separate step; fatoority does not produce an image file here.

## If something goes wrong

| Symptom | What to check |
| --- | --- |
| No embedded payload can be read | Use signed XML that contains QR data, or create a signed invoice first. |
| Generation reports missing seller fields | Supply the seller name and VAT identifier in the invoice. |
| Payload exceeds a length limit | Check field byte lengths, including UTF-8 text, and the encoded payload length. |
| QR scanning returns unexpected text | Feed the encoded payload directly to the renderer; avoid extra encoding or wrapping. |

Next, [validate the invoice's QR and signature checks](validation.md).
See the [QR reference](../reference/qr.md) for payload limits and error types.
