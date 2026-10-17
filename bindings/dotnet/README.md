# Fatoority C# bindings

See the [C# / .NET reference](https://docs.fatoority.com/reference/bindings/csharp/)
for guide examples, API requests, errors, and runtime contracts.

The `Fatoority` NuGet package exposes the SDK under namespace `Fatoora` and targets
.NET 8 or later. Native libraries live under `runtimes/<rid>/native`; NuGet selects
the library for the application's platform.

```csharp
using Fatoora;

using var key = SigningKey.Generate();
var pem = key.ToPem();
using var restored = SigningKey.FromPem(pem);

using var address = Address.New(
    "SA", "الرياض", "King Fahd Rd", "1234", "12345", null, "", "حي العليا");
Console.WriteLine(address.City());
```

All opaque owners implement `IDisposable`. Dispose owned return values as well as
objects you construct. `Dispose()` is idempotent; calls after disposal throw
`ObjectDisposedException`. Rust operations that consume an invoice or builder
leave its outer owner disposable, but subsequent operations fail with
`BindingErrorException`.

String inputs reject invalid UTF-16 and embedded NUL. Optional strings preserve
null versus empty. Decimal arguments and outputs use invariant decimal strings.
Native errors throw `BindingErrorException` with the native message; `Inner`
exposes `Code()`, `Message()`, and `DetailsJson()` and is itself disposable.
Releasing native memory does not guarantee erasure of secrets or managed copies.

`Bytes.AsSlice()` returns a disposable borrowed view. Call `Clone()` to obtain an
independent `byte[]`, or `WithSpan()` for a scoped read. Active reads retain the
native buffer even if its owner is disposed concurrently. Later reads fail once
the source is disposed. Disposing a view while a read is active throws
`InvalidOperationException`; retry after the read completes.

```csharp
using var bytes = restored.ToDer();
using var view = bytes.AsSlice();
byte[] der = view.Clone();
```

Methods using `&mut self` reject conflicting concurrent calls. Native network
methods block the calling thread. For asynchronous HTTP and cancellation, use
`Prepare*`, send the owned request with your HTTP client, and call `Decode` with
the response status and bytes. Requests own their credentials and decoding state.

## Build and test

From the repository root, with Rust, Python 3.11+, and the .NET 8 SDK installed:

```sh
python3 scripts/check_dotnet.py
python3 scripts/package_dotnet.py --output-dir dist/dotnet
python3 scripts/check_dotnet.py --package-dir dist/dotnet
```

The checker copies the native library beside the test executable. The package
check creates a fresh consumer using a local NuGet source, without a project
reference or native library search-path overrides. `DOTNET` and `CARGO_TARGET_DIR`
can select alternate tool and build locations.

Local packaging includes the host RID. CI tests Linux, Windows, and macOS, then
combines their native artifacts into one package. Only platforms represented in
the package are supported. CI uploads a `nuget` artifact. Version tags publish that tested artifact to
NuGet.org through trusted publishing after all platform consumers pass. For a locally built package:

```sh
dotnet add package Fatoority --version 0.4.4 --source /absolute/path/to/dist/dotnet
```

Release `linux-x64` assets are built and tested on glibc 2.28 (AlmaLinux 8).
They require glibc 2.28 or newer; musl/Alpine is not included. Locally built
packages inherit the build host's libc requirements.

## Regenerate

The generator uses `mqqz/diplomat` commit
`8f2d28f1b39653320db1446ebd8fd264cc8a166d`. This revision provides strict UTF-16
encoding, synchronized borrowed-span access, and native handle retention during
borrowed reads. It permits scoped read-only spans from disposable sources while
preserving the other borrowing restrictions.

```sh
python3 scripts/install_dotnet_generator.py
python3 scripts/generate_dotnet.py
python3 scripts/generate_dotnet.py --check
```

Installation tests the backend and installs into `.tools/diplomat-fork`.
It leaves the upstream generator on PATH for other languages.
`DIPLOMAT_TOOL_DOTNET` overrides the C# generator path. The combined
`scripts/generate_bindings.py --check` checks C# as well as the other bindings.
Edit generator inputs or the fork, then regenerate; do not edit generated C#.

The .NET contracts cover encoding, optional strings, structured errors, disposal,
concurrent borrowed reads, keys, invoice signing, hashes against frozen SDK
fixtures, prepared requests, response decoding, and owned snapshots. These tests
run locally without contacting ZATCA.

## License

Original project code is `MIT OR Apache-2.0`. The bundled native validator also
contains ZATCA-derived rule predicates and messages under the terms recorded in
[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md), which the NuGet license
metadata references. The package includes the upstream notice and LGPL v3/GPL v3
texts under `licenses/zatca/`. The GPL text is incorporated by LGPL v3; it does
not separately relicense all project code.

Downstream distribution must account for applicable source and relinking
requirements. Source and build instructions are in the
[Fatoority repository](https://github.com/mqqz/fatoority), with versioned source
under the corresponding release tag. No ZATCA SDK JAR is bundled.
