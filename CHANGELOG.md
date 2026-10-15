# Changelog

## [0.4.3] - Unreleased

- Add Kotlin/JVM bindings with a Java-friendly API, deterministic ownership,
  coroutine helpers, and Android AAR packaging for arm64 and x86-64.
- Publish JVM and Android packages under `com.fatoority` on Maven Central, with
  signed artifacts, sources, API documentation, and package-consumer tests.
- Support GPG signing subkeys and increase Android emulator memory for the
  16 KiB page-size tests.
- Replace prerelease crypto dependencies with stable versions so fresh Cargo
  consumers build successfully; add a fresh-consumer CI check.
- Synchronize Rust, Python, npm, NuGet, and Maven packages at 0.4.3.

## [0.4.2] - 2026-10-12

- Add C#/.NET 8 bindings with deterministic disposal, strict string conversion,
  and prepared requests for asynchronous HTTP through caller-owned transports.
- Package native libraries for Linux x64 (glibc 2.28+), Windows x64, and macOS
  arm64; publish tested NuGet packages on version tags using trusted publishing.
- Include the bundled ZATCA notices and license texts in the NuGet package.
- Add the official .NET SDK comparison harness, recorded hashing/signing/validation
  benchmarks, and reproduction instructions.
- Document C# support in the README and synchronize Rust, Python, npm, and NuGet
  package versions at 0.4.2.

## [0.4.1] - 2026-10-11

- Add Diplomat JavaScript/TypeScript bindings for Node and browsers, with async
  fetch APIs backed by Rust request preparation and response decoding.
- Build a size-optimized WASM artifact with losslessly compressed UBL schemas,
  cryptographic host randomness and explicit validation time.
- Add JS/TS documentation, runtime/browser/package tests and artifact size limits.
- Publish the tested npm tarball on version tags using the JavaScript release workflow.
- Preserve Rust validation errors for invalid JS options and document the compiled
  SDK-derived rules and their upstream licenses.
- Synchronize Rust, Python and npm packages at 0.4.1.

## [0.4.0] - 2026-10-11

### Breaking changes

- Rename the project and repository to `fatoority`, the Python distribution to
  `fatoority`, and the CLI crate to `fatoora-cli` with executable `fatoora`.
  Install Python with `pip install fatoority` and the CLI with
  `cargo install fatoora-cli`. Python still imports as `fatoora`; Rust crate
  names and C/C++ interfaces remain unchanged. Documentation now lives at
  https://docs.fatoority.com.
- Before switching Python distributions, uninstall the previous distribution,
  then install `fatoority`; both distributions provide the same `fatoora` import package.
- The CLI executable is now `fatoora`. It shares its name with the official
  ZATCA SDK executable; use an explicit path when both are installed.

### Distribution

- Publish the first `fatoority` Python distribution and `fatoora-cli` crate.
  Existing packages remain available under their historical names.
- Synchronize `fatoora-core`, `fatoora-derive`, `fatoora-ffi`, `fatoora-cli`, and
  the Python distribution at 0.4.0.

## [0.3.0] - 2026-10-11

Upgrade bindings and their native library together. This release replaces the
C ABI and Python native loader, adds complete local ZATCA validation, and
removes libxml2 from ordinary builds and distributed artifacts.

### Breaking changes

- Replace handwritten C exports with Diplomat-generated `fatoora_Type_method`
  symbols. Recompile C/C++ clients against the matching generated headers.
  Strings are length-delimited UTF-8 views, numeric getters write to
  `DiplomatWrite`, and fallible results contain an owned `BindingError`.
  See the [binding migration guide](docs/development/diplomat.md).
- Python keeps its high-level API but removes `FfiLibrary`, the CFFI loader,
  and custom native-library/header environment overrides. Install the matching
  wheel, which bundles its Nanobind extension and native library.
- XML entrypoints require UTF-8 XML 1.0 without DTDs and enforce an 8 MiB limit
  for complete documents, including signed output. Signing rejects mismatched
  keys, different existing certificates, invalid reference bindings, and
  externally owned or ambiguous signatures.

### Added

- Complete local ZATCA validation through Rust, CLI, C/C++, and Python: XSD,
  all 257 CEN/KSA assertions, and applicable signature/QR integrity checks.
  Reports distinguish rejection, missing context, and execution failure.
  See [local validation](docs/reference/invoice-validation.md).
- Generated C++ ownership wrappers and Python native bindings for invoices,
  signing, keys, CSRs, credentials, and HTTP responses.
- Seeded property tests, bounded XML/QR/signing fuzz targets, and independent
  canonicalization, signature-tampering, and schema-negative regressions.

### Fixed

- Preserve unrelated XML bytes, comments, processing instructions, and extension
  content during signing. Re-signing with the same certificate and preserved
  signing time produces identical bytes and verifies the complete result.
- Align hash exclusions with exact QR identifiers and preserve valid text across
  excluded subtree boundaries. Preserve the certificate's original SPKI encoding
  in QR tag 8 and escape issuer text consistently with SignedProperties digests.
- Preserve invoice flags and free-text values, including CR/CRLF, across XML
  import and output. Reject truncated or duplicate QR TLV tags.
- Preserve literal CSR distinguished-name values and improve binding ownership,
  failure recovery, HTTP, and CLI regression coverage.
- Validate large UBL decimal values with a narrowly scoped compatibility shim;
  retain lexical, declared-type, attribute, ordering, and namespace constraints.
  Resolve bundled schema paths consistently across platforms.

### Distribution

- Synchronize all four Rust crates and the Python package at 0.3.0.
- Use roxmltree for XML interpretation, xml-sec for C14N 1.1, and xsd-schema for
  XSD validation. libxml2 remains only in optional reference tools.
- Remove libxml2 installation, linking, and bundling from normal builds,
  Linux/macOS/Windows CLI and FFI archives, and Python wheels. Verify the actual
  artifact dependency closure in CI.
- Ship generated C/C++ headers with FFI archives and retain the bundled native
  library layout in repaired Python wheels.

## [0.2.0] - 2026-09-18

This release breaks compatibility with 0.1.x in Rust, the C ABI, Python, and
serialized invoice data. Upgrade bindings and their native library together.

### Breaking changes

- Invoice numbers use the crate-owned `Decimal` type. Rust callers construct
  values from strings or integers; JSON encodes them as decimal strings. Python
  accepts `decimal.Decimal`, `str`, or `int` and rejects floats. C numeric inputs
  are UTF-8 strings, and numeric getters return owned strings. See the
  [numeric migration guide](docs/reference/numbers.md#bindings-and-migration).
- Rust `InvoiceBuilder` configuration methods consume and return the builder.
  Chain calls or assign their result back. `build()` consumes the builder on
  success and failure. C and Python retain mutable setters, but their builder
  handles are consumed by `build()` as well.
- `SignedInvoice` exposes `xml()` for borrowing and `into_xml()` for consuming
  its exact signed XML. C and Python expose copied and consuming XML accessors;
  discard a handle after using the consuming accessor.
- Public errors retain typed causes and structured details using crate-owned
  types. C errors are opaque handles with accessor functions and an explicit
  free function. Rebuild C/C++ callers against the generated 0.2.0 headers.
  See [error ownership and classification](docs/reference/errors.md).
- Invoice HTTP responses retain their status and body alongside typed validation
  results. Use `outcome()` or `ensure_accepted()` to distinguish invoice
  acceptance from a successful HTTP request. Handle rejected and unknown
  outcomes explicitly. Cleared invoice XML is decoded through the response
  accessor. See the [API client guide](docs/reference/api-client.md).
- XML generation uses inherent `FinalizedInvoice::to_xml()` and
  `to_xml_with_format()` methods. Remove `ToXml` imports and replace
  `to_xml_pretty()` calls with `to_xml()`. `InvoiceView` and `InvoiceXml` are
  internal, and `PartyRole` is sealed against downstream implementations.
- Addresses use `district` for XML `CitySubdivisionName`; the redundant
  `subdivision` field and constructor argument have been removed in every
  binding. See the [public API migration](docs/development/api-audit.md#migration).

### Fixes and additions

- Validate decimal amounts and totals without floating-point conversions,
  including half-up rounding, VAT category aggregation, supplied line VAT,
  prepayments, and payable-rounding adjustments.
- Enforce validated wrapper invariants during deserialization and expose
  structured invoice validation reports. Rust XML validation covers XSD;
  complete ZATCA business-rule validation remains separate work.
- Preserve optional address fields during XML import and output.
- Preserve HTTP error status and bodies, reject unexpected redirects, and
  report malformed success responses without treating them as acceptance.
- Correct Arabic CSR property decoding, certificate-template ASN.1 encoding,
  CSR name ordering, and validation of CSR capability flags.
- Align signing and QR output with recorded SDK behavior, including the QR
  timestamp and SignedProperties digest when re-signing formatted XML.
- Add a frozen 53-case ZATCA SDK `238-R3.4.8` corpus and offline regressions for
  canonical bytes, hashes, signatures, QR fields, XSD results, and CSRs. The
  [SDK compatibility notes](docs/development/sdk-parity.md) describe coverage
  limits and the recorded QR rounding and foreign-currency differences.
- License original project code under `MIT OR Apache-2.0` and include
  [third-party notices](THIRD_PARTY_NOTICES.md). Upstream materials retain their
  own terms; the notice records unresolved provenance separately.

### Distribution

- Report the CLI package version through the `--version` flag.
- Synchronize Rust crates and the Python package at 0.2.0.
- Validate versions and publication tags in CI and dry-run Cargo packaging.
- Build wheels and native assets on release PRs before tagging. Native GitHub
  assets upload only after every native build succeeds.
- Use the Cargo lockfile for native builds. Test installed wheels by calling
  the native library, and restrict Windows wheels to the supported AMD64 target.
- Bundle the generated ABI header in Python wheels so address constructors and
  the complete binding declarations are available outside a source checkout.
- Repair Windows wheels for runtime-loaded DLL dependencies. Windows CLI and
  FFI ZIP archives include vcpkg DLLs and their installed license material.
  Windows CLI users should extract the complete archive before running it.
- Require CFFI 1.17+ so Windows loads repaired wheel dependencies through the
  registered DLL search directories.

[0.2.0]: https://github.com/mqqz/fatoority/compare/v0.1.3...v0.2.0

[0.3.0]: https://github.com/mqqz/fatoority/compare/v0.2.0...v0.3.0

[0.4.0]: https://github.com/mqqz/fatoority/compare/v0.3.0...v0.4.0
