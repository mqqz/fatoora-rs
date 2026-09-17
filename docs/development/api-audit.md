# Supported public API

The public API covers invoice construction, XML import, signing, validation,
QR generation, credential creation, and submission. Implementation helpers stay
private. Operation inputs and outputs use crate-owned or standard-library types;
Serde integration remains supported.

Generate the full signature reference from the checkout with
`cargo doc -p fatoora-core --no-deps`. This page records the supported workflows
and their contracts. The generated reference is authoritative for the complete
method and field inventory.

## Entry points

| Module | Supported surface |
| --- | --- |
| crate root | `Decimal`, `DecimalError`, `Error`, `ErrorKind`, `Diagnostic`, `DiagnosticSeverity` |
| `config` | `Config`, `EnvironmentType` |
| `csr` | `CsrProperties`, `SigningKey`, `Csr`, `CsrError` |
| `invoice` | Builder, finalized/signed invoices, invoice data and totals, parties, lines, validated value types, flags, QR payloads, and field-validation errors |
| `invoice::sign` | `InvoiceSigner`, read-only `SignedProperties`, `SigningError`, `invoice_hash_base64_from_xml_str` |
| `invoice::xml` | `XmlFormat`, `InvoiceXmlError`, and `parse` |
| `invoice::xml::parse` | Finalized/signed XML import, corresponding file helpers, `ParseError` |
| `invoice::validation` | Bundled-XSD validation, validation reports and findings, `XmlValidationError` |
| `api` | `ZatcaClient`, `CsidCredentials<Compliance>` / `<Production>`, response data, `InvoiceOutcome`, `HttpResponseError`, `ZatcaError` |

Domain enums and result types remain public where callers construct inputs,
inspect results, or handle errors. `InvoiceData`, `InvoiceTotalsData`,
`VatBreakdown`, and `SignedProperties` expose read-only accessors. Public structs
such as `Address` and validation findings support ordinary value construction.

## Visibility and extension points

- `InvoiceView` is internal. Both invoice types expose inherent `data()` and
  `totals()` methods.
- `InvoiceXml` is a private serialization wrapper.
- XML serialization uses inherent `FinalizedInvoice` methods. There is no public
  `ToXml` trait.
- `PartyRole` is sealed: callers can use it as a generic bound, but only
  `SellerRole` and `BuyerRole` implement it. `Seller` and `Buyer` are the usual
  construction types.
- The unused `TokenScope` trait is removed. API methods select the required
  `CsidCredentials<Compliance>` or `CsidCredentials<Production>` type directly.
- XML/backend nodes, serializers, signing keys from dependencies, and HTTP clients
  are implementation details. No public backend injection or custom XSD API is
  supported.

## Construction and errors

`InvoiceBuilder::new(InvoiceType) -> InvoiceBuilder` creates a builder.
Configuration methods consume and return it; `build(self)` returns
`Result<FinalizedInvoice, InvoiceError>` and consumes the builder on failure too.
Conditional configuration therefore reassigns the returned builder.

Amounts use `Decimal`, including `LineItem` constructors and builder adjustments.
Parse exact values from strings with `Decimal::parse`; bindings pass decimal
strings. Validated country, currency, date, timestamp, and VAT ID wrappers reject
invalid values through constructors and deserialization.

Module operations return their module errors (`CsrError`, `InvoiceError`,
`SigningError`, `InvoiceXmlError`, `ParseError`, `XmlValidationError`,
`QrCodeError`, `ZatcaError`, or `DecimalError`). Callers can convert these into
`fatoora_core::Error`; `ErrorKind` provides shared classification. Diagnostic text
may change. Callers should use structured variants, fields, and codes.

## XML and signing

The principal signatures are:

```rust
// FinalizedInvoice
pub fn to_xml(&self) -> Result<String, InvoiceXmlError>;
pub fn to_xml_with_format(&self, format: XmlFormat) -> Result<String, InvoiceXmlError>;
pub fn hash_base64(&self) -> Result<String, SigningError>;
pub fn sign(self, signer: &InvoiceSigner) -> Result<SignedInvoice, SigningError>;

// InvoiceSigner
pub fn from_pem(cert_pem: &str, private_key_pem: &str) -> Result<Self, SigningError>;
pub fn from_der(cert_der: &[u8], private_key_der: &[u8]) -> Result<Self, SigningError>;
pub fn sign_xml(&self, xml: &str) -> Result<String, SigningError>;

// SignedInvoice
pub fn xml(&self) -> &str;
pub fn into_xml(self) -> String;
pub fn to_xml_base64(&self) -> String;
```

`to_xml()` uses two-space indentation. `to_xml_with_format()` accepts compact
output or explicit indentation. `to_xml_pretty()` has been removed because it
was identical to `to_xml()`.

`parse_finalized_invoice_xml(&str)` returns
`Result<FinalizedInvoice, ParseError>`; `parse_signed_invoice_xml(&str)` returns
`Result<SignedInvoice, ParseError>`. Seller address import preserves additional street and additional number.
`district` maps to XML `CitySubdivisionName`. The redundant `subdivision` field
has been removed. Import does not promise a lossless model round trip. Their `_file` variants accept
`impl AsRef<Path>` and return the same result types.

Signed invoices preserve the supplied signed XML on import, or the output of
signing. They expose no formatting methods. Raw `sign_xml()` may parse and
serialize its input; preserve its returned output when storing or submitting it.
Signing metadata remains readable through `signed_properties()` and invoice
accessors.

## Validation guarantees

| Operation | Guarantee |
| --- | --- |
| Builder `build()` | Implemented field/range checks and computed totals |
| XML import | Supported parser/model checks, including supplied amounts |
| Signing | Signature material and signed XML generated |
| Signed XML import | Signature material extracted; authenticity is unverified |
| `validate_xml_invoice_from_str(&str, &Config)` | Bundled XSD check; returns `Result<(), XmlValidationError>` |
| `validate_xml_invoice_report_from_str(&str, &Config)` | Same XSD check; returns `Result<ValidationReport, XmlValidationError>` |

Reports list only completed layers. Schema violations become findings in a
report; malformed XML returns an error. These operations do not establish full
business-rule compliance or signature trust.

## Submission

`ZatcaClient::new(Config)` returns `Result<ZatcaClient, ZatcaError>`.
`check_invoice_compliance()` takes `&SignedInvoice` and
`&CsidCredentials<Compliance>`. Reporting and clearance take `&SignedInvoice`,
`&CsidCredentials<Production>`, `clearance_status: bool`, and
`accept_language: Option<&str>`. These async operations return
`Result<ValidationResponse, ZatcaError>`.

A decoded 2xx response is `Ok`. Call `ensure_accepted()` to require endpoint
acceptance, or inspect `outcome()` for `Accepted`, `Rejected`, or `Unknown`.
`http_status()` preserves the received status. Clearance responses expose
`cleared_invoice_base64()` and fallible `cleared_invoice_xml()`; decoding the
returned invoice does not verify authenticity.

Non-2xx responses return `ZatcaError::Response` with status, raw body, and an
optional typed validation response. A malformed 2xx body returns
`ZatcaError::ResponseDecode`. A failed `ensure_accepted()` retains the response
in `ZatcaError::NotAccepted`.

## Contract coverage

- [Public consumer workflows](../../fatoora-core/tests/public_api.rs):
  construction, direct serialization, import/signing, validation, and structured
  failures.
- [Compile-fail consumers](../../fatoora-core/tests/ui/public_api): private
  helpers, removed traits/aliases, sealed roles, and signed XML formatting.
- [Public submission](../../fatoora-core/tests/public_submission.rs): local HTTP
  requests, credentials, payloads, acceptance, business rejection, HTTP rejection,
  compliance, and cleared XML. Child processes isolate the endpoint override.
- [Builder ownership](../../fatoora-core/tests/builder_ownership.rs),
  [signed XML ownership](../../fatoora-core/tests/signed_xml_ownership.rs), and
  [numeric contracts](../../fatoora-core/tests/numeric_contract.rs) cover values
  and ownership in more detail.
- [Examples](../../fatoora-core/examples) compile as external consumers. The live
  API example test is ignored by default and requires explicit opt-in.

Run the offline workspace checks with:

```sh
SKIP_ZATCA_LIVE_API=1 CARGO_INCREMENTAL=0 cargo test --workspace --locked --offline
```

The live API tests are skipped by that environment variable. SDK compatibility
coverage remains tracked separately in issue #2. Binding migration remains in
issue #5. The FFI uses these core methods; its authoritative declarations are the
[generated header](../../fatoora-ffi/include/fatoora_ffi.h) and
[exports](../../fatoora-ffi/src/lib.rs), rather than a duplicate signature list here.

## Migration

Remove imports of `ToXml` and call `FinalizedInvoice::to_xml()` directly. Replace
`to_xml_pretty()` with `to_xml()`. Replace public `InvoiceView` bounds with the
concrete invoice type or a consumer-owned abstraction. Custom `PartyRole`
implementations and direct use of `InvoiceXml` are no longer supported.

Address callers must replace `subdivision` with `district`. The C address and
inline seller/buyer constructors now take one district argument after postal
code; rebuild callers against the regenerated header and matching library.
Python constructors likewise accept only `district`.
