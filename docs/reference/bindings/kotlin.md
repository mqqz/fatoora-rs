---
title: Kotlin, Java and Android ZATCA E-Invoicing Library
description: Install fatoority from Maven Central for Kotlin, Java, or Android. Find platform requirements and ZATCA integration examples.
---

# Kotlin / Java bindings

The Kotlin/JVM bindings expose the Rust SDK as `com.fatoora` classes through JNA.
Java callers use static factories and overloads with ordinary return values;
native failures throw `BindingException`. The public API does not expose Kotlin
`Result` or unsigned types with JVM-mangled method names.

## Install from Maven Central

Use a published release from Maven Central. Java/Kotlin imports remain
`com.fatoora`; the Maven group is `com.fatoority`.

For desktop Gradle projects, add this to `build.gradle.kts`:

```kotlin
repositories { mavenCentral() }
dependencies {
    implementation("com.fatoority:fatoority:0.4.3")
}
```

For Maven, add this dependency to `pom.xml` (Maven Central is used by default):

```xml
<dependency>
  <groupId>com.fatoority</groupId>
  <artifactId>fatoority</artifactId>
  <version>0.4.3</version>
</dependency>
```

For Android, include `mavenCentral()` in the repositories under
`dependencyResolutionManagement` in `settings.gradle.kts`, then add the Android
artifact to your app's `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.fatoority:fatoority-android:0.4.3")
}
```

Choose the desktop JAR or Android AAR, not both. They bundle the native libraries
for their supported platforms and resolve JNA and coroutines transitively.
Consumers do not need Rust or a separate native-library build.

For unpublished versions or development builds, see the
[package README](https://github.com/mqqz/fatoority/tree/main/bindings/kotlin#build-and-test)
for the local Maven repository, Android SDK setup and test commands.

| Artifact | Runtime | Bundled native platforms |
| --- | --- | --- |
| `com.fatoority:fatoority:0.4.3` | Java 8+ | Linux x86-64, Windows x86-64, macOS arm64 |
| `com.fatoority:fatoority-android:0.4.3` | Android API 26+ | arm64-v8a, x86_64 |

The desktop JAR includes JNA native resource directories. Linux CI assets require
glibc 2.28+; musl/Alpine is not included. Local native builds inherit the host's
libc requirements. Android libraries are separate NDK builds, packaged under
`jni/<abi>` in the AAR. Desktop binaries cannot be used on Android.

Windows x86-64 also requires the [Microsoft Visual C++ v14 x64 runtime](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).
The native DLL imports `VCRUNTIME140.dll`; it is not bundled in the JAR.

## Kotlin and Java

```kotlin
import com.fatoora.*

SigningKey.generate().use { key ->
    SigningKey.fromPem(key.toPem()).use { restored ->
        check(key.toPem() == restored.toPem())
    }
}
Address.create("SA", "الرياض", "Street", "1234", "12345", null, "", "حي العليا").use { address ->
    println(address.city())
    check(address.additionalStreet() == null)
    address.additionalNumber()?.use { check(it.value() == "") }
}
```

```java
import com.fatoora.*;

try (SigningKey key = SigningKey.generate();
     SigningKey restored = SigningKey.fromPem(key.toPem())) {
    if (!key.toPem().equals(restored.toPem())) throw new AssertionError();
}
try {
    Config.create(99);
} catch (BindingException e) {
    System.err.println(e.getCode() + ": " + e.getMessage());
}
```

Use environment `0` for nonproduction, `1` for simulation, `2` for production.
Configuration, CSR and credentials must agree on the environment. Native API
names follow the bridge in camel case; Rust `new` becomes `create`.

## Ownership and values

| Bridge value | Public JVM value |
| --- | --- |
| Owned opaque | `AutoCloseable`; Kotlin `use` or Java try-with-resources |
| Optional text input | Nullable `String`; `null` differs from `""` |
| Optional text output | Nullable `Text`; read `value()` and close it |
| Decimal | Invariant decimal string |
| Unsigned byte / short / int | Checked `Int` / `Int` / `Long` |
| Unsigned 64-bit counter | `BigInteger`, range 0 through 2^64−1 |
| Binary input / copied output | `ByteArray` / Java `byte[]` |
| Native failure | `BindingException(code, message, detailsJson)` |

Close objects returned by methods as well as those you construct. Native errors
are copied to managed data and freed immediately; exceptions need no cleanup.
`Bytes.asSlice()` copies bytes under the owner lock, so the returned array survives
closing its native owner. Strings reject lone UTF-16 surrogates and embedded NUL.

Calls acquire all participating owners in a fixed lock order. Concurrent calls
on the same object serialize; `close()` waits for active calls and is idempotent.
Later calls throw `IllegalStateException`. Operations on independent owners can
run concurrently. Consumed builders/invoices remain closeable but reject further
use with a native error. Phantom references provide nondeterministic fallback
cleanup; freeing native memory does not guarantee secret erasure.

Import `com.fatoora`, not the generated implementation package `com.fatoora.raw`.
Raw bindings do not provide these ownership and synchronization guarantees.

## Blocking calls and coroutines

Blocking native HTTP calls are available to Java and Kotlin. Kotlin extensions
`postCsrForCcsidAsync`, `postCcsidForPcsidAsync`, `renewCsidAsync`,
`checkInvoiceComplianceAsync`, `reportSimplifiedInvoiceAsync`, and
`clearStandardInvoiceAsync` dispatch them through `withContext(Dispatchers.IO)`.

```kotlin
// Within a suspend function; keep owners open until the call completes.
client.reportSimplifiedInvoiceAsync(invoice, credentials, false).use { response ->
    response.ensureAccepted()
}
```

Cancellation cannot interrupt an in-flight native call. Its locks remain held
until completion. If cancellation discards a completed owning result during the
return dispatch, the coroutine wrapper closes that result. Use prepared requests
with a cancellable JVM HTTP client when transport-level cancellation is needed.

`prepareReportSimplifiedInvoice`, for example, returns an owned `InvoiceRequest`:
read `url()`, `method()`, `headersJson()` and `body()`, send exactly those values,
then call `decode(status, responseBytes)` and `ensureAccepted()` on the returned
response. Prepared requests own their bytes and decoding context independently
of the original credentials/invoice. Headers contain credentials: do not log them.

## Android

Use the Android artifact alone. It supplies JNA's Android dependency and shrinker
rules and declares the Internet permission. It supports 64-bit ABIs with 16 KiB
ELF alignment. Run network, signing and validation work off the UI thread; the
coroutine HTTP extensions use the IO dispatcher.

Android native TLS uses bundled Mozilla/WebPKI roots. Android user-installed CAs
and app network-security configuration do not modify that trust store. Prepared
requests let apps use their own HTTP client and certificate policy.

CI builds both ABIs and runs device tests on API 26 and API 35 with 16 KiB pages. Tests cover Java calls,
Arabic strings, nullable values, errors, client creation, frozen SDK hash parity
and concurrent close. Desktop tests additionally exercise signing, prepared
requests, result decoding and cancellation cleanup on Java 8.

## License

Original SDK code is `MIT OR Apache-2.0`. Native packages contain ZATCA-derived
rule predicates and messages under their own terms and include
`THIRD_PARTY_NOTICES.md` and `licenses/zatca/`. See the
[third-party notices](https://github.com/mqqz/fatoority/blob/main/THIRD_PARTY_NOTICES.md).
