---
title: ZATCA API Integration - Reporting and Clearance
description: Prepare ZATCA API credentials, report simplified invoices, and handle acceptance with fatoority. Understand compliance checks and standard-invoice clearance.
---

# Connect to ZATCA APIs

Use the API client to submit invoices and inspect the gateway's response. This
walkthrough reports a simplified invoice to the non-production environment and
checks whether reporting was accepted. It requires network access and credentials.

## Choose the operation

| Your task | Operation | Credentials |
| --- | --- | --- |
| Test an invoice during onboarding | Compliance check | Compliance credentials |
| Submit a simplified invoice | Reporting | Production-type credentials for the selected environment |
| Submit a standard invoice | Clearance | Production-type credentials for the selected environment |

A credential's type and its environment are separate. Production-type credentials
can target non-production, simulation, or production; the client and credentials
must agree. Every example below uses **non-production**. Changing only the client
environment does not convert credentials issued for another environment.

## Obtain credentials

1. [Generate a CSR and private key](csr.md) for the target environment.
2. Obtain the onboarding one-time password (OTP) through the appropriate ZATCA flow,
   then submit the CSR to request compliance credentials.
3. Use those credentials to complete the required invoice compliance checks.
4. Request production-type credentials for that environment, then retain the returned
   token and secret for reporting or clearance.

See the [credential endpoint reference](../reference/api-client.md#post_csr_for_ccsid)
and [ZATCA developer portal](https://sandbox.zatca.gov.sa/IntegrationSandbox) for the
request fields and environment-specific onboarding requirements. A successful
compliance check alone is not reporting or clearance acceptance.

## Prepare the inputs

Use your own `signed.xml`: a simplified invoice signed with the certificate and
key associated with your credentials. The offline guide's public test certificate
is not a substitute for credentials issued to you.

Set `ZATCA_TOKEN` and `ZATCA_SECRET` in the environment of the process running the
example. Do not paste credentials into source files. The example reads these names
and fails before sending a request if either value is missing.

## Run the example

Choose your language, then follow its setup and run instructions.

=== "Rust"
    Install [Rust and Cargo](https://www.rust-lang.org/tools/install), then create a project:

    ```sh
    cargo new fatoority-guide
    cd fatoority-guide
    cargo add fatoora-core
    ```

    Add the async runtime:

    ```sh
    cargo add tokio --features macros,rt-multi-thread
    ```

    Save the code below as `src/main.rs`. Put the input files in the project root and run:

    ```sh
    cargo run
    ```

    [Download this example](../assets/examples/rust/api.rs).

    Set `ZATCA_TOKEN` and `ZATCA_SECRET` in your process environment before running.
    The example makes a real request to the non-production gateway.


    ```rust
    --8<-- "docs/assets/examples/rust/api.rs"
    ```


=== "Python"
    Install the package in your Python environment:

    ```sh
    pip install fatoority
    ```

    Save the code as `api.py` beside the input files, then run:

    ```sh
    python api.py
    ```

    [Download this example](../assets/examples/python/api.py).
    See [Python setup](../reference/bindings/python.md) for package details.

    Set `ZATCA_TOKEN` and `ZATCA_SECRET` in your process environment before running.
    The example makes a real request to the non-production gateway.

    This example uses a blocking request; run it away from your application's UI thread.


    ```python
    --8<-- "docs/assets/examples/python/api.py"
    ```


=== "JavaScript"
    Use Node.js 22 or later. In a new working folder, install the package:

    ```sh
    npm install fatoority
    ```

    Save the code as `api.mjs` beside the input files, then run:

    ```sh
    node api.mjs
    ```

    [Download this example](../assets/examples/javascript/api.mjs).
    These examples run in Node.js and can also be adapted to TypeScript. In a browser,
    replace filesystem reads with your application's file input and configure the WASM
    asset as described in the [browser setup](../reference/bindings/javascript.md).
    Keep objects in the WASM instance that created them; do not pass them between workers.

    Set `ZATCA_TOKEN` and `ZATCA_SECRET` in your process environment before running.
    The example makes a real request to the non-production gateway.

    Browser requests also depend on gateway CORS. Keep private credentials on a trusted server.


    ```js
    --8<-- "docs/assets/examples/javascript/api.mjs"
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

    [Download this example](../assets/examples/csharp/api.cs).
    The `using` declarations release native objects. Check the
    [supported .NET platforms](../reference/bindings/csharp.md) before deployment.

    Set `ZATCA_TOKEN` and `ZATCA_SECRET` in your process environment before running.
    The example makes a real request to the non-production gateway.

    This example uses a blocking request; run it away from your application's UI thread.


    ```csharp
    --8<-- "docs/assets/examples/csharp/api.cs"
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

    [Download this example](../assets/examples/kotlin/api.kt).
    `use` releases each native object. For an existing project, or Android's separate
    artifact and file handling, follow [Kotlin setup](../reference/bindings/kotlin.md).
    The binding also supports Maven; its dependency coordinates are listed there.

    Set `ZATCA_TOKEN` and `ZATCA_SECRET` in your process environment before running.
    The example makes a real request to the non-production gateway.

    This example uses a blocking request; run it away from your application's UI thread.
    The binding also provides `reportSimplifiedInvoiceAsync` for coroutine callers.


    ```kotlin
    --8<-- "docs/assets/examples/kotlin/api.kt"
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

    [Download this example](../assets/examples/java/api.java).
    Try-with-resources releases native objects. The library itself supports Java 8+;
    see [Java setup](../reference/bindings/kotlin.md) for platform prerequisites,
    Gradle installation, and Android configuration.

    Set `ZATCA_TOKEN` and `ZATCA_SECRET` in your process environment before running.
    The example makes a real request to the non-production gateway.

    This example uses a blocking request; run it away from your application's UI thread.


    ```java
    --8<-- "docs/assets/examples/java/api.java"
    ```


=== "C"
    Download and extract the `fatoora-ffi-*` archive for your platform from
    [GitHub Releases](https://github.com/mqqz/fatoority/releases).
    Save the example as `api.c` in the extracted folder, beside the input files.

    On Linux, compile the example and the supplied adapter, then run:

    ```sh
    cc -std=c11 -Iinclude api.c src/fatoora.c -L. -lfatoora_ffi -Wl,-rpath,'$ORIGIN' -o api
    ./api signed.xml
    ```

    [Download this example](../assets/examples/c/api.c).
    For other platforms, follow the [C installation and linking reference](../reference/bindings/c.md).
    The cleanup section releases handles and returned strings, including on failure.

    Set `ZATCA_TOKEN` and `ZATCA_SECRET` in your process environment before running.
    The example makes a real request to the non-production gateway.

    This example uses a blocking request; run it away from your application's UI thread.


    ```c
    --8<-- "docs/assets/examples/c/api.c"
    ```



<span id="response-receipt-and-acceptance"></span>

## Check the result

The example prints `Invoice reporting accepted` only after checking the reporting
outcome. An HTTP 2xx response that decodes successfully does not by itself mean the
invoice was accepted.

| Outcome | What to do |
| --- | --- |
| Accepted | Record the response and retain warnings. For compliance, this means only that the compliance check passed. |
| Rejected | Inspect validation messages and correct the invoice before another submission. |
| Unknown | Inspect the original status fields; missing, unfamiliar, or contradictory evidence cannot establish acceptance. |

Non-2xx responses are errors and retain HTTP status and response details when
available. Avoid blind retries when the result of a submission is uncertain.

## Use clearance for a standard invoice

Choose the clearance operation with a standard invoice and credentials for the
same environment. Check the clearance outcome, then retrieve the returned cleared
invoice if your workflow needs the gateway document. Save that XML directly.

Acceptance does not guarantee the optional cleared document is present or decodable.
Decoding the field establishes UTF-8 text only; it does not parse XML or verify a
signature. The [clearance reference](../reference/api-client.md#clear_standard_invoice)
describes the operation and response accessors.

## If something goes wrong

| Symptom | What to check |
| --- | --- |
| Missing credential variable | Set both named environment variables in the process that runs the example. |
| Authentication or authorization error | Check the token, secret, credential type, and environment together. |
| Invoice rejected | Read the gateway's validation messages and compare them with [local validation](validation.md). |
| Network error or timeout | Check connectivity and the selected endpoint; determine whether a request reached the gateway before retrying. |
| Accepted clearance without usable XML | Handle the missing or invalid document explicitly; do not silently substitute the submitted XML. |

See the [API reference](../reference/api-client.md) for onboarding, renewal, compliance,
reporting, clearance, and complete response contracts.
