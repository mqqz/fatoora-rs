# Fatoority Kotlin / Java bindings

The public API is `com.fatoora`. It uses JNA and runs on Java 8+.
The Android AAR supports API 26+ on `arm64-v8a` and `x86_64`.
See the [Kotlin / Java reference](https://docs.fatoority.com/reference/bindings/kotlin/)
for installation, requests, ownership and coroutine behavior.

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

For Maven, add this dependency to `pom.xml` (Maven Central is used by default):

```xml
<dependency>
  <groupId>com.fatoority</groupId>
  <artifactId>fatoority</artifactId>
  <version>0.4.4</version>
</dependency>
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
for their supported platforms and resolve JNA and coroutines transitively.
Consumers do not need Rust or a separate native-library build.

For an unpublished version, use the [local build](#build-and-test) below.
Publisher setup is documented in the
[release guide](https://docs.fatoority.com/development/releases/#maven-central-publishing).

## Usage

```kotlin
import com.fatoora.*

SigningKey.generate().use { key ->
    SigningKey.fromPem(key.toPem()).use { restored ->
        check(restored.toPem() == key.toPem())
    }
}
Address.create("SA", "الرياض", "King Fahd Rd", "1234", "12345").use { address ->
    println(address.city())
}
```

Java uses the same classes, static factories, overloads and ordinary exceptions:

```java
import com.fatoora.*;

try (SigningKey key = SigningKey.generate()) {
    String pem = key.toPem();
}
```

Every owned native object is `AutoCloseable`. Close returned owners as well as
objects you construct. Close is idempotent, waits for active calls, and later
calls throw `IllegalStateException`. A phantom-reference queue is a fallback,
not a substitute for closing secrets and large objects promptly. Native release
does not erase managed strings or byte arrays.

Native failures throw `BindingException` with `code`, `message`, and `detailsJson`
(Java getters). Error data is copied and its native owner freed before throwing.
`null` and empty strings stay distinct; invalid UTF-16 and embedded NUL are
rejected. Decimal values use invariant decimal strings. Unsigned counters use
`BigInteger`; byte data uses `byte[]` / `ByteArray`. `Bytes.asSlice()` copies the
native data while holding its owner's lock.

The `com.fatoora.raw` package is an implementation detail. Its direct use bypasses
ownership, text validation and concurrency guards. Import `com.fatoora` in apps.

## Build and test

Requires Rust, Python 3.11+, JDK 17 and a C toolchain. Generated sources and the
Gradle wrapper are checked in; consumers run on Java 8+. From the repo root:

```sh
python3 scripts/build_kotlin.py
bindings/kotlin/gradlew -p bindings/kotlin test -PnativeDir="$PWD/target/jvm-release"
python3 scripts/check_kotlin.py
```

The Maven repository is `bindings/kotlin/build/repository`. A local build embeds
the host native library. CI combines Linux x86-64 (glibc 2.28+), Windows x86-64
and macOS arm64 in its `kotlin-maven` artifact. Add the local repository in your
app's Gradle configuration to test an unpublished build:

```kotlin
repositories {
    maven { url = uri("/absolute/path/to/fatoority/bindings/kotlin/build/repository") }
    mavenCentral()
}
dependencies { implementation("com.fatoority:fatoority:0.4.4") }
```

For Android, install SDK 35, build-tools 35.0.0 and NDK 28.2.13676358:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
python3 scripts/build_kotlin.py --android --ndk "$ANDROID_HOME/ndk/28.2.13676358"
bindings/kotlin/gradlew -p bindings/kotlin -Pandroid=true :android:connectedDebugAndroidTest
```

Use `com.fatoority:fatoority-android:0.4.4` from that repository in Android apps.
Do not add the desktop artifact alongside it. The AAR bundles both Android native
libraries and consumer shrinker rules; its Maven metadata supplies JNA's AAR and
coroutines. Native ELF segments support 16 KiB pages. Android TLS uses bundled
Mozilla/WebPKI roots, not Android user-installed CAs or app network-security
configuration. Use prepared requests with your app's HTTP client when you need
that trust policy. Blocking API calls must run off the main thread.

Windows x86-64 also requires the [Microsoft Visual C++ v14 x64 runtime](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).
The native DLL imports `VCRUNTIME140.dll`; it is not bundled in the JAR.

## Regeneration

```sh
python3 scripts/install_kotlin_generator.py
python3 scripts/generate_kotlin.py
python3 scripts/generate_kotlin.py --check
```

The installer pins upstream Diplomat including #1295 and applies the tracked
Kotlin patch, running backend tests first. `DIPLOMAT_TOOL_KOTLIN` overrides its
isolated tool path. Both raw bindings and the Java-friendly facade are generated;
do not edit `generated/` by hand.

## License

Original SDK code is `MIT OR Apache-2.0`. The native libraries also contain
ZATCA-derived rule predicates and messages under their own terms. Packages ship
`THIRD_PARTY_NOTICES.md`, `LICENSE-MIT`, `LICENSE-APACHE`, and `licenses/zatca/`.
See [third-party notices](../../THIRD_PARTY_NOTICES.md).
