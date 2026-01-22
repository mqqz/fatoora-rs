# API Audit (Core + FFI)

This page captures the current public surface, a proposed target shape, and issues to resolve while finalizing the API. Notes are based on current code; older parity docs may be stale.

## Current Surface (Condensed)
- Core modules: `config`, `csr`, `invoice`, `invoice::sign`, `invoice::xml`, `invoice::validation`, `api` in `fatoora-core/src/lib.rs`.
- Core public API still exposes external crate types (e.g., `Currency`, `CountryCode`, `DateTime<Utc>`, `SigningKey`, `CertReq`, `reqwest::Error`).
- FFI exports cover config, CSR, signing keys, invoice builder/sign/parse/accessors, validation, and ZATCA API in `fatoora-ffi/src/lib.rs`.
- The generated C header is missing some Rust exports (totals accessors, party/address getters, validation response fields).

## Proposed Final API Shape
- Core goal: public API only exposes crate-owned types; external crates remain internal.
- Core config:
  - `Environment` enum; `Config` uses bundled XSD only.
  - `Config::new(env)` uses bundled XSD; no custom XSD inputs in public API.
- Core CSR:
  - `CsrProperties::new(...)` + `CsrProperties::from_properties_str(...)`.
  - `Csr` opaque struct with `to_der_bytes`, `to_pem_string`, `to_base64`, `to_pem_base64`.
  - `SigningKey` wrapper with `from_pem/der`, `to_pem`, `to_der`.
  - `CsrBundle { csr, key }`.
- Core invoice model:
  - Newtypes: `CountryCode(String)`, `CurrencyCode(String)`, `Timestamp { seconds, nanos }`.
  - `Address`, `VatId`, `OtherId`, `InvoiceNote`, `Party`, `Seller`, `Buyer`.
  - `InvoiceType` + `InvoiceSubType`, `OriginalInvoiceRef`.
  - `InvoiceFlags` bitflags.
  - `InvoiceBuilder::new(required)` + setters; `FinalizedInvoice` + `SignedInvoice` getters.
- Core signing:
  - `InvoiceSigner::from_pem/der` takes bytes/strings; `sign(invoice) -> SignedInvoice`.
  - `sign_xml` returns `SignedInvoice` (or a `SignedXml` struct) for parity.
- Core API client:
  - `CsidCredentials { scope: CsidScope, ... }` (avoid generic `TokenScope`).
  - `ZatcaError` contains strings only (no external error types).
- FFI shape:
  - Opaque handles and `*_free`.
  - `FfiBytes { ptr, len }` for binary.
  - Replace large constructors with `FfiInvoiceBuilderConfig` + setters.
  - `FfiDateTime { seconds, nanos }`, `FfiCountryCode`/`FfiCurrencyCode` as strings.
  - Mirror core types: `FfiCsr`, `FfiSigningKey`, `FfiCsrBundle`, `FfiCsidCredentials`, `FfiInvoiceType`.

## Final API Checklist
- Core public API exposes only crate-owned types (no external crate types in signatures).
- Core uses string/bytes inputs for CSR/signing and avoids filesystem I/O in public API.
- Core removes filesystem-based helpers from the public API to avoid confusion.
- Country code, currency code, and timestamp are string wrappers with validation at construction.
- Remove custom XSD inputs entirely; Config always uses bundled schemas.
- `Config` uses bundled XSD only; no custom XSD inputs in public API.
- `InvoiceBuilder` has a small required set; optional fields are set via setters.
- `InvoiceType` and `InvoiceFlags` are consistent across core + FFI.
- `SignedInvoice` and `FinalizedInvoice` expose identical read-only accessors.
- All fallible functions return a single top-level error type or a small set of module errors.
- FFI uses `FfiResult<T>` everywhere; no panics cross the boundary.
- FFI exports include all accessors (totals, parties, validation response) and headers match Rust.
- FFI constructors avoid long parameter lists; prefer config handles + setters.
- No FFI functions require filesystem access; accept strings/bytes instead.
- FFI types are `#[repr(C)]`, opaque handles only, no generics/trait objects.

## Proposed Signature List (Core)
This list is intentionally minimal and string/bytes-only at the public boundary.

### config
- `pub enum Environment { NonProduction, Simulation, Production }`
- `pub struct Config { ... }`
- `impl Config { pub fn new(env: Environment) -> Self; pub fn env(&self) -> Environment; }`

### csr
- `pub struct CsrProperties { ... }`
- `impl CsrProperties { pub fn new(...fields...) -> Result<Self, Error>; pub fn from_properties_str(s: &str) -> Result<Self, Error>; }`
- `pub struct Csr { ... }`
- `impl Csr { pub fn to_der_bytes(&self) -> Vec<u8>; pub fn to_pem_string(&self) -> String; pub fn to_base64(&self) -> String; pub fn to_pem_base64(&self) -> String; }`
- `pub struct SigningKey { ... }`
- `impl SigningKey { pub fn from_der(bytes: &[u8]) -> Result<Self, Error>; pub fn from_pem(pem: &str) -> Result<Self, Error>; pub fn to_der_bytes(&self) -> Vec<u8>; pub fn to_pem_string(&self) -> String; }`
- `pub struct CsrBundle { pub csr: Csr, pub key: SigningKey }`
- `impl CsrProperties { pub fn build(&self, key: &SigningKey, env: Environment) -> Result<Csr, Error>; pub fn build_with_rng(&self, env: Environment) -> Result<CsrBundle, Error>; }`

### invoice model
- `pub struct CountryCode(String); pub struct CurrencyCode(String); pub struct Timestamp(String)`
- `pub struct Address { ... }`
- `pub struct VatId(String); pub struct OtherId { ... }`
- `pub struct InvoiceNote { ... }`
- `pub struct Party { ... }; pub type Seller = Party; pub type Buyer = Party;`
- `pub enum InvoiceSubType { Standard, Simplified }`
- `pub enum InvoiceType { Tax(InvoiceSubType), Prepayment(InvoiceSubType), CreditNote(InvoiceSubType, OriginalInvoiceRef, String), DebitNote(InvoiceSubType, OriginalInvoiceRef, String) }`
- `pub struct OriginalInvoiceRef { ... }`
- `bitflags! { pub struct InvoiceFlags: u8 { ... } }`
- `pub struct LineItem { ... }`
- `pub struct InvoiceTotals { ... }`
- `pub struct FinalizedInvoice { ... }`
- `pub struct SignedInvoice { ... }`

### invoice builder
- `pub struct InvoiceBuilder { ... }`
- `pub struct RequiredInvoiceFields { ... }`
- `impl InvoiceBuilder { pub fn new(required: RequiredInvoiceFields) -> Self; pub fn set_buyer(&mut self, buyer: Buyer) -> &mut Self; pub fn set_note(&mut self, note: InvoiceNote) -> &mut Self; pub fn set_allowance(&mut self, reason: String, amount: f64) -> &mut Self; pub fn add_line_item(&mut self, item: LineItem) -> &mut Self; pub fn set_flags(&mut self, flags: InvoiceFlags) -> &mut Self; pub fn enable_flags(&mut self, flags: InvoiceFlags) -> &mut Self; pub fn disable_flags(&mut self, flags: InvoiceFlags) -> &mut Self; pub fn build(self) -> Result<FinalizedInvoice, Error>; }`

### invoice signing + XML
- `pub struct InvoiceSigner { ... }`
- `impl InvoiceSigner { pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, Error>; pub fn from_der(cert_der: &[u8], key_der: &[u8]) -> Result<Self, Error>; pub fn sign(&self, invoice: FinalizedInvoice) -> Result<SignedInvoice, Error>; pub fn sign_xml(&self, xml: &str) -> Result<SignedInvoice, Error>; }`
- `pub fn invoice_hash_base64_from_xml(xml: &str) -> Result<String, Error>;`
- `pub fn parse_finalized_invoice_xml(xml: &str) -> Result<FinalizedInvoice, Error>;`
- `pub fn parse_signed_invoice_xml(xml: &str) -> Result<SignedInvoice, Error>;`
- `pub fn validate_xml_invoice(xml: &str, config: &Config) -> Result<(), Error>;`

### api client
- `pub enum CsidScope { Compliance, Production }`
- `pub struct CsidCredentials { ... }`
- `pub struct ZatcaClient { ... }`
- `impl ZatcaClient { pub fn new(config: Config) -> Result<Self, Error>; pub async fn check_invoice_compliance(&self, invoice: &SignedInvoice, creds: &CsidCredentials) -> Result<ValidationResponse, Error>; pub async fn report_simplified_invoice(&self, invoice: &SignedInvoice, creds: &CsidCredentials, clearance_status: bool, accept_language: Option<&str>) -> Result<ValidationResponse, Error>; pub async fn clear_standard_invoice(&self, invoice: &SignedInvoice, creds: &CsidCredentials, clearance_status: bool, accept_language: Option<&str>) -> Result<ValidationResponse, Error>; pub async fn post_csr_for_ccsid(&self, csr: &Csr, otp: &str) -> Result<CsidCredentials, Error>; pub async fn post_ccsid_for_pcsid(&self, creds: &CsidCredentials) -> Result<CsidCredentials, Error>; pub async fn renew_csid(&self, creds: &CsidCredentials) -> Result<CsidCredentials, Error>; }`

## Proposed Signature List (FFI)
Names are illustrative; exact naming can follow `fatoora_` prefix rules.

### config
- `FfiConfig* fatoora_config_new(FfiEnvironment env);`
- `FfiConfig* fatoora_config_with_xsd_source(FfiEnvironment env, FfiXsdSource source);`
- `void fatoora_config_free(FfiConfig*);`

### csr + key
- `FfiResult_FfiCsrProperties fatoora_csr_properties_from_str(const char* s);`
- `FfiResult_FfiSigningKey fatoora_signing_key_from_pem(const char* pem);`
- `FfiResult_FfiSigningKey fatoora_signing_key_from_der(const uint8_t* der, size_t len);`
- `FfiResult_FfiString fatoora_signing_key_to_pem(FfiSigningKey* key);`
- `FfiResult_FfiBytes fatoora_signing_key_to_der(FfiSigningKey* key);`
- `FfiResult_FfiCsr fatoora_csr_build(FfiCsrProperties* props, FfiSigningKey* key, FfiEnvironment env);`
- `FfiResult_FfiCsrBundle fatoora_csr_build_with_rng(FfiCsrProperties* props, FfiEnvironment env);`
- `FfiResult_FfiString fatoora_csr_to_base64(FfiCsr* csr);`
- `FfiResult_FfiString fatoora_csr_to_pem_base64(FfiCsr* csr);`
- `FfiResult_FfiBytes fatoora_csr_to_der(FfiCsr* csr);`
- `FfiResult_FfiString fatoora_csr_to_pem(FfiCsr* csr);`
- `void fatoora_csr_free(FfiCsr*); void fatoora_signing_key_free(FfiSigningKey*);`

### invoice builder
- `FfiResult_FfiInvoiceBuilder fatoora_invoice_builder_new(FfiInvoiceType type, const char* id, const char* uuid, const char* issue_time, const char* currency_code, const char* previous_hash, uint64_t counter, const char* payment_means_code, FfiVatCategory vat_category, FfiParty seller);`
- `FfiResult_bool fatoora_invoice_builder_set_buyer(FfiInvoiceBuilder*, FfiParty buyer);`
- `FfiResult_bool fatoora_invoice_builder_set_note(FfiInvoiceBuilder*, FfiInvoiceNote note);`
- `FfiResult_bool fatoora_invoice_builder_set_allowance(FfiInvoiceBuilder*, const char* reason, double amount);`
- `FfiResult_bool fatoora_invoice_builder_add_line_item(FfiInvoiceBuilder*, FfiLineItem item);`
- `FfiResult_bool fatoora_invoice_builder_set_flags(FfiInvoiceBuilder*, uint8_t flags);`
- `FfiResult_FfiFinalizedInvoice fatoora_invoice_builder_build(FfiInvoiceBuilder*);`
- `void fatoora_invoice_builder_free(FfiInvoiceBuilder*);`

### invoice accessors
- `FfiResult_FfiString fatoora_invoice_to_xml(FfiFinalizedInvoice*);`
- `FfiResult_FfiString fatoora_invoice_hash_base64(FfiFinalizedInvoice*);`
- `FfiResult_FfiParty fatoora_invoice_seller(FfiFinalizedInvoice*);`
- `FfiResult_FfiParty fatoora_invoice_buyer(FfiFinalizedInvoice*);`
- `FfiResult_FfiTotals fatoora_invoice_totals(FfiFinalizedInvoice*);`
- `FfiResult_FfiString fatoora_signed_invoice_xml(FfiSignedInvoice*);`
- `FfiResult_FfiString fatoora_signed_invoice_qr(FfiSignedInvoice*);`
- `FfiResult_FfiTotals fatoora_signed_invoice_totals(FfiSignedInvoice*);`
- `void fatoora_invoice_free(FfiFinalizedInvoice*); void fatoora_signed_invoice_free(FfiSignedInvoice*);`

### signing + XML parse
- `FfiResult_FfiSigner fatoora_signer_from_pem(const char* cert_pem, const char* key_pem);`
- `FfiResult_FfiSigner fatoora_signer_from_der(const uint8_t* cert_der, size_t cert_len, const uint8_t* key_der, size_t key_len);`
- `FfiResult_FfiSignedInvoice fatoora_invoice_sign(FfiFinalizedInvoice*, FfiSigner*);`
- `FfiResult_FfiSignedInvoice fatoora_invoice_sign_xml(FfiSigner*, const char* xml);`
- `FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml(const char* xml);`
- `FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml(const char* xml);`

### validation
- `FfiResult_bool fatoora_validate_xml_str(FfiConfig*, const char* xml);`

### api client
- `FfiResult_FfiZatcaClient fatoora_zatca_client_new(FfiConfig*);`
- `FfiResult_FfiCsidCredentials fatoora_csid_credentials_new(FfiEnvironment env, FfiCsidScope scope, bool has_request_id, uint64_t request_id, const char* token, const char* secret);`
- `FfiResult_FfiValidationResponse fatoora_zatca_check_compliance(FfiZatcaClient*, FfiSignedInvoice*, FfiCsidCredentials*);`
- `FfiResult_FfiValidationResponse fatoora_zatca_report_simplified_invoice(FfiZatcaClient*, FfiSignedInvoice*, FfiCsidCredentials*, bool clearance_status, const char* accept_language);`
- `FfiResult_FfiValidationResponse fatoora_zatca_clear_standard_invoice(FfiZatcaClient*, FfiSignedInvoice*, FfiCsidCredentials*, bool clearance_status, const char* accept_language);`
- `void fatoora_zatca_client_free(FfiZatcaClient*);`

## Issues / Inconsistencies / Improvements
- External types exposed in core public API:
  - `CountryCode`, `Currency`, `DateTime<Utc>` in `fatoora-core/src/invoice.rs`.
  - `Currency` and `DateTime` in `fatoora-core/src/invoice/builder.rs`.
  - `k256::SigningKey` + `x509_cert::CertReq` in `fatoora-core/src/csr.rs`.
  - `reqwest::Error` leaked in `fatoora-core/src/api.rs`.
  - `CountryCodeParseErr` exposed in `fatoora-core/src/invoice.rs`.
- FFI header out of sync with Rust exports:
  - Missing totals, party/address getters, validation response accessors in `fatoora-ffi/include/fatoora_ffi.h` vs `fatoora-ffi/src/lib.rs`.
- FFI builder constructor is too large and brittle:
  - `fatoora_invoice_builder_new(...)` has many params in `fatoora-ffi/src/lib.rs`.
- FFI still relies on filesystem:
  - `fatoora_config_with_xsd` and `fatoora_csr_properties_parse` in `fatoora-ffi/src/lib.rs`.
  - `CsrProperties::parse_csr_config` in `fatoora-core/src/csr.rs`.
- Inconsistent invoice-type exposure:
  - FFI uses `FfiInvoiceTypeKind`/`FfiInvoiceSubType` but getters return `u8` and are not exported in headers.
- Validation response accessors missing in headers:
  - `fatoora_validation_response_*` and `fatoora_validation_results_*_len` exist in Rust but are missing from `fatoora-ffi/include/fatoora_ffi.h`.
