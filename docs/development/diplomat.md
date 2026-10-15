# Diplomat bindings

Diplomat generates the C, C++, Python and JavaScript/TypeScript interfaces from `fatoora-ffi`.
Direct C# generation uses a separately pinned fork; see the
[C# build instructions](../reference/bindings/csharp.md) and the
[C# generation workflow](#c-net).
The Rust core remains independent of the binding framework. The public Python
API in [api.py](https://github.com/mqqz/fatoority/blob/main/bindings/python/fatoora/api.py) wraps the generated private
`fatoora._native` extension and supplies decimal conversion, exceptions, and
object lifetime management.

The bridge is divided by capability:

| Source | Responsibilities |
| --- | --- |
| [common.rs](https://github.com/mqqz/fatoority/blob/main/fatoora-ffi/src/common.rs) | Structured errors, strict text conversion, panic boundaries, owned optional text |
| [crypto.rs](https://github.com/mqqz/fatoority/blob/main/fatoora-ffi/src/crypto.rs) | Configuration, keys, CSRs, certificates, signing, owned bytes |
| [invoice.rs](https://github.com/mqqz/fatoority/blob/main/fatoora-ffi/src/invoice.rs) | Invoice builders, parsing, snapshots, totals, XML, hashes, validation |
| [api.rs](https://github.com/mqqz/fatoority/blob/main/fatoora-ffi/src/api.rs) | Credentials, ZATCA requests, response outcomes, validation messages |

Generated C headers live in [bindings/c/generated](https://github.com/mqqz/fatoority/tree/main/bindings/c/generated), C++ headers in
[bindings/cpp](https://github.com/mqqz/fatoority/tree/main/bindings/cpp), and Nanobind sources in
[bindings/python/native/generated](https://github.com/mqqz/fatoority/tree/main/bindings/python/native/generated).
The old C ABI and CFFI implementation have been removed. `FfiLibrary` and
`fatoora.native` are no longer public entry points; import from `fatoora` or its
documented Python modules.

## Python contracts

Install from the repository root:

```sh
python -m pip install ./bindings/python
```

Building requires Rust, the repository's native library dependencies, CMake,
Python development headers, and a C++20 compiler. Build isolation installs the
pinned Nanobind dependency. The wheel bundles `_native` and `fatoora_ffi`.

Decimal arguments accept `Decimal`, decimal strings, or integers. Floats and
booleans are rejected. Rust validates UTF-8 and rejects embedded NUL. Exceptions
retain `.code`, `.kind`, and structured `.details`; unknown numeric error codes
remain available. The facade copies error data before releasing its native owner.

Objects support `close()` and context managers. Closing releases the facade's
native reference; subsequent operations raise `InvalidInputError`. Builder setters
validate input before updating state, allowing correction after an input error.
`build()` consumes the builder's inner state on success and validation failure.
Signing consumes a finalized invoice, and `SignedInvoice.into_xml()` consumes a
signed invoice. Their outer owners remain safe to release after consumption.

Invoice data, parties, addresses, line items, and response getters return owned
snapshots. They remain usable after their source object is closed. Python copies
native byte views into `bytes` through a small Nanobind adapter, without NumPy; XML and other text outputs are owned strings.

## Blocking requests and concurrency

ZATCA methods are synchronous. The custom Nanobind bindings in
[client_bindings.cpp](https://github.com/mqqz/fatoority/blob/main/fatoora-ffi/src/client_bindings.cpp) add private
`_blocking_*` methods that release the GIL during requests. The Python facade
acquires an `RLock` for every argument owner in a consistent order and holds those
locks through the call. This prevents concurrent close or consumption of a handle
while native code uses it. Other Python threads can continue running.

`_native` is an implementation detail. Calling its generated methods directly
bypasses the facade's locking and error conversion. Native C and C++ callers must
provide their own synchronization, including exclusive access during mutation or
consumption. Mutable objects expose no borrowed child fields. `Bytes.as_slice()`
is a read-only view valid for the lifetime of its immutable `Bytes` owner.

## C and C++ ownership

For ordinary C clients, the [C API](c-api.md) exposes the full bridge
through one header, plain strings, shared status codes, and named-field options.
The generated interface below remains the native ABI used by language bindings.

Include `InvoiceBuilder.h` for C or `fatoora/InvoiceBuilder.hpp` for C++ and link
`fatoora_ffi`. C++ types live in namespace `fatoora`; standalone clients require
C++17. See the [C contract](https://github.com/mqqz/fatoority/blob/main/fatoora-ffi/tests/diplomat_contract.c) and
[C++ contract](https://github.com/mqqz/fatoority/blob/main/fatoora-ffi/tests/diplomat_contract.cpp) for complete clients.

Generated C symbols use `fatoora_Type_method`, such as
`fatoora_InvoiceBuilder_build`. This is a breaking ABI replacement. Recompile
clients against the generated headers distributed with their library version.

Fallible results contain a success value or an owned `BindingError`. Inspect
`is_ok` before reading the union. Destroy every owned object and error exactly
once with its generated destroy function. C++ uses `std::unique_ptr` to release
these owners automatically. Optional values use the generated optional
representation; absence is distinct from an empty string.

String inputs are length-delimited byte views. Malformed UTF-8 and embedded NUL
return InvalidInput errors. Enum-like inputs use validated integer values, so
unknown values produce errors. Callers must still supply valid pointers and obey
reference lifetimes.

Fallible Rust operations catch unwinding panics and return Internal errors,
including when a panic payload's destructor panics. Abort-mode panics, allocation
aborts, and invalid native pointers cannot be recovered through this boundary.

## Generate and verify

Generated files are checked-in build inputs. Regenerate them after changing bridge
signatures or documentation; do not edit generated files directly.

```sh
cargo install diplomat-tool --version 0.16.1 --locked
python3 scripts/install_dotnet_generator.py
python scripts/generate_bindings.py
python scripts/generate_bindings.py --check
cargo test -p fatoora-ffi --locked
python scripts/check_native_bindings.py
python scripts/check_c_reference.py
python -m pip wheel --no-deps ./bindings/python -w /tmp/fatoora-wheels
```

Install the resulting wheel in a fresh virtual environment, then run
[wheel_smoke.py](https://github.com/mqqz/fatoority/blob/main/bindings/python/tests/wheel_smoke.py) and the
[Python tests](https://github.com/mqqz/fatoority/tree/main/bindings/python/tests). Do not add the source package to
`PYTHONPATH`. Verify that the installed extension loads its bundled shared library,
with the build-tree library unavailable. Linux dependency entries must use a
library basename with `$ORIGIN`; macOS uses `@rpath` and `@loader_path`.

[check_native_bindings.py](https://github.com/mqqz/fatoority/blob/main/scripts/check_native_bindings.py) builds C11 and
C++17 clients on Linux/macOS, passes a signed XML fixture to the C++ contract, and
honors `CC`, `CXX`, and `CARGO_TARGET_DIR`. `DIPLOMAT_TOOL` selects an alternate
path to the generator.

Versions are pinned: Diplomat macro and generator 0.16.1, runtime 0.16.0, and
Nanobind 2.12.0. Update the macro and generator together. Nanobind's generated
deleter uses internal headers, so its pin also requires cross-language tests.

The replacement C11 and C++17 contracts have passed locally on Linux. The Linux CPython 3.14 installed wheel passed all 53 Python tests, including
HTTP concurrency checks, and the bundled-library smoke test. Windows, macOS, and other
Python versions require their platform CI checks; local Linux results do not
establish those outcomes. The [parity map](ffi-parity.md) records capability and
test coverage separately.

## JavaScript / TypeScript

The [JS package](../reference/bindings/javascript.md) uses a WASM artifact and a small async fetch facade. `prepare_*` APIs are also exposed to native bindings so callers can supply their own transport. Requests own their bytes, headers and decoding context. Existing native blocking methods remain available.

See the [JS/TS reference](../reference/bindings/javascript.md) for installation and usage.
The build applies the `wasm-release` profile, lossless schema compression and
Binaryen `wasm-opt -Oz`; raw and gzip size limits run before packaging.

Run `npm ci --prefix bindings/js`, `python3 scripts/build_js.py`, and `python3 scripts/check_js_package.py` after generating bindings. The JavaScript CI job also checks TypeScript declarations and exercises Chromium.

## C# / .NET

The [C# reference](../reference/bindings/csharp.md) covers installation and runtime
contracts. The generator uses `mqqz/diplomat` commit
`8f2d28f1b39653320db1446ebd8fd264cc8a166d`. It installs separately from the
upstream generator used by the other bindings:

```sh
python3 scripts/install_dotnet_generator.py
python3 scripts/generate_dotnet.py
python3 scripts/generate_dotnet.py --check
python3 scripts/check_dotnet.py
```

`DIPLOMAT_TOOL_DOTNET` overrides `.tools/diplomat-fork/bin/diplomat-tool`.
The installer applies the patch and tests the backend before installation.
Generated C# lives in `bindings/dotnet/generated`; the combined generation check
also checks these files. All opaque Rust bridge types opt into .NET disposal.

The .NET workflow builds native assets for each runner, tests host packages,
combines the assets, and tests the combined NuGet package on each platform.
The `dotnet.yml` workflow publishes that exact artifact to NuGet.org on version
tags after every platform consumer passes. See the
[release workflow](releases.md#nuget-artifact-and-trusted-publishing) for setup and retries.

## Kotlin / Java / Android

The [Kotlin reference](../reference/bindings/kotlin.md) covers the JVM facade and
Android package. The installer pins upstream Diplomat at
`d53b78666c85f6e3bad34d70c0dbd22052b4cabd` (including #1295) and applies
`scripts/patches/diplomat-kotlin.patch`. The patch fixes nullable opaque results,
failed string-write cleanup, Boolean finalizer configuration and finalizer
ownership visibility, with backend
regression tests. It does not modify the generator used for other languages.

```sh
python3 scripts/install_kotlin_generator.py
python3 scripts/generate_kotlin.py
python3 scripts/generate_kotlin.py --check
python3 scripts/build_kotlin.py
bindings/kotlin/gradlew -p bindings/kotlin test -PnativeDir="$PWD/target/jvm-release"
python3 scripts/check_kotlin.py
```

`DIPLOMAT_TOOL_KOTLIN` overrides `.tools/diplomat-kotlin/bin/diplomat-tool`.
The shared generation check includes Kotlin. `generated/raw` contains Diplomat
output; `generated/facade` contains generated Java-friendly adapters. Edit the
bridge, generator patch or facade generator and regenerate, never these outputs.
The facade runtime owns handles and locks; its Java 8 phantom-reference cleanup
replaces raw finalizer ownership as each returned handle is adopted.

`kotlin.yml` checks generated output, Java 8 contracts, packaged Java consumers,
three desktop native platforms, two Android ABIs and emulator tests on API 26/35.
It uploads a local Maven repository and Android artifacts without publishing to
an external registry. Android TLS uses explicit bundled WebPKI roots; desktop
TLS continues to use the platform verifier.
