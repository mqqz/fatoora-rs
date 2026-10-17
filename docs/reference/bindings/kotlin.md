---
title: Kotlin, Java and Android ZATCA E-Invoicing Library
description: Install fatoority from Maven Central for Kotlin, Java, or Android. Find platform requirements and ZATCA integration examples.
---

# Kotlin and Java package reference

Use `com.fatoora` classes to build, sign, and validate invoices and send ZATCA API
requests on the JVM or Android. Methods return ordinary values or native objects;
failures throw `BindingException`.

## Install from Maven Central

Use a published release from Maven Central. Java/Kotlin imports remain
`com.fatoora`; the Maven group is `com.fatoority`.

For desktop Gradle projects, add this to `build.gradle.kts`:

```kotlin
repositories { mavenCentral() }
dependencies {
    implementation("com.fatoority:fatoority:0.4.4")
}
```

For Android, include `mavenCentral()` in the repositories under
`dependencyResolutionManagement` in `settings.gradle.kts`, then add the Android
artifact to your app's `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.fatoority:fatoority-android:0.4.4")
}
```

Choose the desktop JAR or Android AAR, not both. They bundle the native libraries
for their supported platforms and resolve their runtime dependencies transitively.
Consumers do not need Rust or a separate native-library build.

| Artifact | Runtime | Bundled native platforms |
| --- | --- | --- |
| `com.fatoority:fatoority:0.4.4` | Java 8+ | Linux x86-64, Windows x86-64, macOS arm64 |
| `com.fatoority:fatoority-android:0.4.4` | Android API 26+ | arm64-v8a, x86_64 |

Linux requires glibc 2.28+; musl/Alpine is not included. Desktop binaries cannot
be used on Android; use the Android artifact for Android applications.

Windows x86-64 also requires the [Microsoft Visual C++ v14 x64 runtime](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).
The native DLL imports `VCRUNTIME140.dll`; it is not bundled in the JAR.

## Kotlin and Java

Select your language for resource handling and examples.

=== "Kotlin"

    ```kotlin
    import com.fatoora.*

    SigningKey.generate().use { key ->
        val privateKeyPem = key.toPem()
        // Store privateKeyPem securely.
    }
    ```

    Use `use` for native owners, including objects returned from methods.
    Optional text getters return `Text?`; read `value()` inside `use` when present.

=== "Java"

    ```java
    import com.fatoora.*;

    try (SigningKey key = SigningKey.generate()) {
        String privateKeyPem = key.toPem();
        // Store privateKeyPem securely.
    }
    ```

    Use try-with-resources for native owners, including returned objects.
    Optional text getters return nullable `Text`; check for null, read `value()`,
    and close the owner when finished.

Use environment `0` for nonproduction, `1` for simulation, `2` for production.
Configuration, CSR and credentials must agree on the environment. Factory names use `create`, such as `Config.create(0)`; other method names use
camel case.

## Ownership and values

| Value | Public JVM value |
| --- | --- |
| Native object | `AutoCloseable`; close after use |
| Optional text input | Nullable `String`; `null` differs from `""` |
| Optional text output | Nullable `Text`; read `value()` and close it |
| Decimal | Invariant decimal string |
| Unsigned byte / short / int | Checked JVM integer / integer / long |
| Unsigned 64-bit counter | `BigInteger`, range 0 through 2^64−1 |
| Binary input / copied output | JVM byte array; copies survive closing their owner |
| Native failure | `BindingException(code, message, detailsJson)` |

Close objects returned by methods as well as those you construct. Native errors
are copied to managed data and freed immediately; exceptions need no cleanup.
`Bytes.asSlice()` copies bytes under the owner lock, so the returned array survives
closing its native owner. Strings reject lone UTF-16 surrogates and embedded NUL.

Calls acquire all participating owners in a fixed lock order. Concurrent calls
on the same object serialize; `close()` waits for active calls and is idempotent.
Later calls throw `IllegalStateException`. Operations on independent owners can
run concurrently. Consumed builders/invoices remain closeable but reject further
use with a native error. Automatic cleanup is nondeterministic; explicitly close owners. Freeing native
memory does not guarantee secret erasure.

Import public classes from `com.fatoora`.

## Errors

Native failures throw `BindingException`. Its code, message, and JSON details are
managed values; exceptions need no cleanup. Invalid UTF-16 and embedded NUL are
rejected. Use [structured error details](../errors.md) to distinguish validation,
input, cryptography, and gateway failures.

=== "Kotlin"

    ```kotlin
    try {
        Config.create(99).use { }
    } catch (error: BindingException) {
        println("${error.code}: ${error.message}")
        println(error.detailsJson)
    }
    ```

=== "Java"

    ```java
    try (Config config = Config.create(99)) {
        // An invalid environment throws before this block.
    } catch (BindingException error) {
        System.err.println(error.getCode() + ": " + error.getMessage());
        System.err.println(error.getDetailsJson());
    }
    ```

## Local validation

| Method | Inputs | Returns |
| --- | --- | --- |
| `Xml.validate(config, xml)` | `Config`, XML string | `true` on schema success; throws for malformed XML or schema rejection |
| `Xml.validateZatca(config, xml, optionsJson)` | `Config`, XML string, nullable options JSON | JSON report string, including rejection or incomplete coverage |
| `Xml.hash(xml)` | XML string | Base64 invoice hash string |

Pass `null` for default options, or a JSON object string with
`previous_invoice_hash` and/or `evaluated_at`. The timestamp uses RFC3339 format;
omission uses one native UTC clock snapshot. Unknown option fields are rejected.
Parse the returned JSON and inspect `is_valid` and `stages`. Missing predecessor
context makes coverage incomplete. Execution failures throw and may carry a
partial report in their JSON details. See the [validation reference](../invoice-validation.md).

Schemas are bundled; validation needs no external SDK or network. Local
validation does not establish gateway acceptance or certificate issuer trust.

## API requests

Create a client with `ZatcaClient.create(config)`. Native HTTP methods block the
calling thread and return objects that must be closed:

| Method | Inputs | Returns |
| --- | --- | --- |
| `postCsrForCcsid(csr, otp)` | `Csr`, OTP string | `CsidCompliance` |
| `postCcsidForPcsid(credentials)` | `CsidCompliance` | `CsidProduction` |
| `renewCsid(credentials, csr, otp, acceptLanguage)` | `CsidProduction`, `Csr`, OTP, nullable language | `CsidProduction` |
| `checkInvoiceCompliance(invoice, credentials)` | `SignedInvoice`, `CsidCompliance` | `ValidationResponse` |
| `reportSimplifiedInvoice(invoice, credentials, clearanceStatus, acceptLanguage)` | `SignedInvoice`, `CsidProduction`, Boolean, nullable language | `ValidationResponse` |
| `clearStandardInvoice(invoice, credentials, clearanceStatus, acceptLanguage)` | `SignedInvoice`, `CsidProduction`, Boolean, nullable language | `ValidationResponse` |

The final `acceptLanguage` argument can be omitted; its default is `null`.

`clearanceStatus` controls the request header; use `false` for ordinary reporting
and `true` for clearance. `acceptLanguage` controls the language header; pass
`null` for no override. It does not describe the response outcome.

A returned response is not necessarily accepted. Call `outcome()` or
`ensureAccepted()`. `clearedInvoiceXml()` returns nullable `Text`; read `value()`,
save the cleared XML, and close that owner. See the [API reference](../api-client.md).

=== "Kotlin"

    Coroutine extensions `postCsrForCcsidAsync`, `postCcsidForPcsidAsync`,
    `renewCsidAsync`, `checkInvoiceComplianceAsync`, `reportSimplifiedInvoiceAsync`,
    and `clearStandardInvoiceAsync` dispatch blocking calls to `Dispatchers.IO`.

    ```kotlin
    // Inside a suspend function, with live client, invoice, and credentials.
    client.reportSimplifiedInvoiceAsync(invoice, credentials, false).use { response ->
        response.ensureAccepted()
    }
    ```

    Keep input owners open until completion. Cancellation cannot interrupt an
    in-flight native call. If cancellation discards a completed result, the
    coroutine wrapper closes it. Use a prepared request with a cancellable HTTP
    transport when you need to interrupt network work.

=== "Java"

    Blocking methods can run on your application's executor. Cancelling a task
    does not interrupt an in-flight native HTTP call. Keep its input owners open
    until completion. Use prepared requests with a cancellable HTTP transport
    when you need to interrupt network work.

### Prepared requests

`prepareReportSimplifiedInvoice`, for example, returns an owned `InvoiceRequest`:
read `url()`, `method()`, `headersJson()` and `body()`, send exactly those values,
then call `decode(status, responseBytes)` and `ensureAccepted()` on the returned
response. HTTP status is a checked integer; the response body is a byte array.
Pass non-2xx responses through decoding too, and disable redirects. Close the
prepared request, its body owner, and decoded response after use. Prepared requests own their bytes and decoding context independently
of the original credentials/invoice. Headers contain credentials: do not log them.

## Android

Use the Android artifact alone. It supplies JNA's Android dependency and shrinker
rules and declares the Internet permission. It supports 64-bit ABIs with 16 KiB
ELF alignment. Run network, signing, and validation work off the UI thread.

Android native TLS uses bundled Mozilla/WebPKI roots. Android user-installed CAs
and app network-security configuration do not modify that trust store. Prepared
requests let apps use their own HTTP client and certificate policy.

## License

Original SDK code is `MIT OR Apache-2.0`. Native packages contain ZATCA-derived
rule predicates and messages under their own terms and include
`THIRD_PARTY_NOTICES.md` and `licenses/zatca/`. See the
[third-party notices](https://github.com/mqqz/fatoority/blob/main/THIRD_PARTY_NOTICES.md).
