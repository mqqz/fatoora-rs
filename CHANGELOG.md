# Changelog

## [0.2.0] - Unreleased

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

- Report the CLI package version with `fatoora-rs-cli --version`.
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

[0.2.0]: https://github.com/mqqz/fatoora-rs/compare/v0.1.3...v0.2.0
