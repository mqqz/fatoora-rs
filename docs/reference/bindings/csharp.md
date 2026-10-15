# C# / .NET bindings

The `Fatoority` NuGet package wraps the Rust SDK through Diplomat-generated C#
classes in namespace `Fatoora`. It targets .NET 8 or later and includes the native
`fatoora_ffi` library for the packaged runtime identifiers (RIDs).

## Build and install

From a source checkout with Rust, Python 3.11+ and the .NET 8 SDK:

```sh
python3 scripts/package_dotnet.py --output-dir dist/dotnet
```

In your application's project directory, install the local package:

```sh
dotnet add package Fatoority --version 0.4.3 --source /absolute/path/to/dist/dotnet
```

A local build includes the host RID. The C# CI workflow tests Linux, Windows and
macOS and assembles their native libraries into a combined `nuget` artifact.
Version tags publish the tested artifact to NuGet.org through trusted publishing;
the commands above also support local packages before publication. Match the application's OS and architecture to a RID included in
the package. NuGet supplies the native asset at runtime, so no library search-path
override is needed.

Release `linux-x64` assets are built and tested on glibc 2.28 (AlmaLinux 8).
They require glibc 2.28 or newer; musl/Alpine is not included. Locally built
packages inherit the build host's libc requirements.

Generated sources are checked in. Building the package does not require Diplomat.
Regeneration uses a pinned fork containing the runtime safety fixes; see the
[binding workflow](../../development/diplomat.md#c-net).

## Example

The guide snippets below are methods from the buildable
[example project](https://github.com/mqqz/fatoority/tree/main/bindings/dotnet/examples).
They use `Fatoora`, `System`, and `System.Text.Json`.

```csharp
--8<-- "bindings/dotnet/examples/SdkExamples.cs:csr"
```

Use environment `0` for nonproduction, `1` for simulation, and `2` for production.
Configuration, CSR generation, and credentials must agree on the environment.
See the [CSR](../../guides/csr.md), [signing](../../guides/invoice-signing.md),
[validation](../../guides/validation.md), and [QR](../../guides/qr.md) guides for
C# examples alongside the other languages.

## Values and ownership

| Rust bridge value | C# representation |
| --- | --- |
| Text input | `string`; invalid UTF-16 and embedded NUL are rejected |
| Optional text input | `string?`; `null` and `""` remain distinct |
| Optional text output | `Text?`; read `Value()` and dispose the owner when present |
| Decimal amount | Invariant decimal string; use `CultureInfo.InvariantCulture` for conversion |
| Invoice counter | `ulong` |
| Owned native object | An `IDisposable` class; use `using` or call `Dispose()` |
| Owned binary output | `Bytes`; call `AsSlice()` and copy with `Clone()` when needed |
| Invoice acceptance | `InvoiceOutcome.Accepted`, `Rejected`, or `Unknown` |

All 31 opaque classes implement `IDisposable`, including returned snapshots and
`BindingError`. Disposal is idempotent; later calls on that wrapper throw
`ObjectDisposedException`. Finalization provides cleanup if disposal is omitted,
but its timing is not deterministic. Releasing an owner does not guarantee
zeroization of secrets or copies exported to managed strings and arrays.

`InvoiceBuilder.Build()`, `Signer.Sign()`, and `SignedInvoice.IntoXml()` consume
inner state. The outer wrapper remains disposable, but reusing consumed state
raises `BindingErrorException`. Build and signing failures can also consume
state. Returned invoice data, totals, addresses, and response children are owned
snapshots and remain usable after their parents are disposed.

For binary output, dispose both the owner and its borrowed view:

```csharp
using Fatoora;

using var key = SigningKey.Generate();
using var bytes = key.ToDer();
using var view = bytes.AsSlice();
byte[] der = view.Clone(); // Independent managed copy.
```

`WithSpan()` provides a scoped, read-only view without copying. An active read
retains native memory through concurrent source disposal. Later reads fail after
the source is disposed. Disposing the view while a read is active throws
`InvalidOperationException`; retry once the read has finished. Conflicting calls
that require mutable access also throw `InvalidOperationException`.

## Errors

```csharp
--8<-- "bindings/dotnet/examples/SdkExamples.cs:errors"
```

`BindingErrorException.Message` contains the native message. `Inner.Code()` uses
the shared [error codes](../errors.md), and `Inner.DetailsJson()` preserves
structured details such as HTTP status and response body. Dispose `Inner` after
reading it. Invalid UTF-16 fails before the native call with
`EncoderFallbackException`; invalid native inputs, including embedded NUL, use
`BindingErrorException`.

## API requests

```csharp
--8<-- "bindings/dotnet/examples/SdkExamples.cs:api"
```

The native client methods block the calling thread. HTTP success alone does not
establish invoice acceptance: inspect `Outcome()` or call `EnsureAccepted()`.
For clearance, read and save `ClearedInvoiceXml()` when present. See the
[API guide](../../guides/api.md#response-receipt-and-acceptance) for rejection,
unknown outcomes, and cleared-document semantics.

| Blocking method | Prepared equivalent | Credential scope / result |
| --- | --- | --- |
| `PostCsrForCcsid` | `PreparePostCsrForCcsid` | CSR and OTP to compliance credentials |
| `PostCcsidForPcsid` | `PreparePostCcsidForPcsid` | Compliance to production credentials |
| `RenewCsid` | `PrepareRenewCsid` | Production credentials, CSR and OTP to renewed credentials |
| `CheckInvoiceCompliance` | `PrepareCheckInvoiceCompliance` | Compliance credentials; validation response |
| `ReportSimplifiedInvoice` | `PrepareReportSimplifiedInvoice` | Production credentials; reporting response |
| `ClearStandardInvoice` | `PrepareClearStandardInvoice` | Production credentials; clearance response |

For asynchronous HTTP or cancellation, use a `Prepare*` method and your own
`HttpClient`. The request exposes `Method()`, `Url()`, `HeadersJson()` (a JSON
array of header pairs), and an owned `Body()`. Copy its bytes before awaiting the
transport. Pass the HTTP status and response bytes to `Decode(ushort, byte[])`,
including non-2xx responses, so Rust can classify gateway errors. Configure the
transport to refuse redirects, and pass your cancellation token to send/read
operations. The generated blocking methods do not accept a cancellation token.

Prepared requests own their wire data, credentials, and decoding context; keep
the request alive until decoding completes. Headers contain credentials and
should not be logged.

## Local validation

`Xml.ValidateZatca(config, xml, optionsJson)` returns a JSON report. Inspect
`is_valid` and `stages`; a rejected document returns a report, while an execution
failure throws an exception that may carry a partial report in its details.
Provide the predecessor hash from invoice history and set `evaluated_at` for
repeatable checks. Omitting the timestamp uses the native clock.

All bundled UBL schemas are embedded. Installed packages do not need the source
checkout, Java, or an external SDK installation. Local validation does not
establish gateway acceptance or certificate issuer trust. See the
[validation reference](../invoice-validation.md).

## Licensing

The native library includes SDK-derived rules and messages subject to the
upstream terms in the bundled
[third-party notices](https://github.com/mqqz/fatoority/blob/main/THIRD_PARTY_NOTICES.md).
Those terms apply to the native component distributed with the C# package, as
they do to other SDK distributions.

## Verification

```sh
python3 scripts/check_dotnet.py
python3 scripts/package_dotnet.py --output-dir dist/dotnet
python3 scripts/check_dotnet.py --package-only --package-dir dist/dotnet
```

The checks compile the guide examples and cover Unicode conversion, optional
strings, errors, disposal, concurrent byte access, key encodings, signing,
frozen SDK hashes, prepared requests, and response snapshots. Package verification
uses a fresh consumer with no project reference or native search-path overrides.
The CI matrix tests the combined NuGet package on Linux, Windows, and macOS.
Local Linux results do not establish Windows/macOS or live gateway acceptance.
