# API Audit (Core + FFI)

This page captures the current public surface, the target shape, and a checklist to resolve while finalizing the API. Notes reflect the current codebase (older parity docs may be stale).

## Current Surface (Updated)
- Core modules: `config`, `csr`, `invoice`, `invoice::sign`, `invoice::xml`, `invoice::validation`, `api` (see `fatoora-core/src/lib.rs`).
- Core public API uses crate-owned types only; external types no longer appear in public signatures (HTTP errors and signing time are strings).
- CSR + signing keys are wrapped in crate-owned types (`SigningKey`, `Csr`) with string/bytes constructors and serializers.
- Invoice timestamp/currency/country codes are validated string wrappers (`InvoiceTimestamp`, `CurrencyCode`, `CountryCode`).
- FFI exports cover config, CSR, signing keys, invoice builder/sign/parse/accessors, validation, and ZATCA API (`fatoora-ffi/src/lib.rs`).
- FFI string handling is strict UTF-8 (no lossy conversion or trimming); interior-NUL returns an error or NULL.
- FFI enums use explicit `repr(i32)` discriminants for ABI stability.
- FFI async calls share a single Tokio runtime (no per-call runtime creation).
- Core defines a unified `ErrorKind`/`Error`; FFI uses the same kind values (1:1 mapping).
- Generated C header is in sync with Rust exports and includes validation accessors, totals/party getters, and invoice type getters.

## Target Shape (Guiding Principles)
- Public API exposes only crate-owned types; external crates stay internal.
- Inputs at the boundary are string/bytes with validation inside the crate.
- FFI is handle-based with `FfiResult<T>` for fallible operations; constructors that cannot fail (e.g., config) return raw handles; no panics cross the boundary.
- Constructors are minimal; setters carry optional/extended fields.

## Final API Checklist
- [x] Core public API exposes only crate-owned types (no external crate types in signatures).
- [x] Core uses string/bytes inputs for CSR/signing and also provides `_file` helpers.
- [x] Country code, currency code, and timestamp are string wrappers with validation at construction.
- [x] Remove custom XSD inputs entirely; `Config` always uses bundled schemas.
- [x] `InvoiceBuilder` has a small required set; optional fields are set via setters.
- [x] `InvoiceType` and `InvoiceFlags` are consistent across core and FFI.
- [x] `SignedInvoice` and `FinalizedInvoice` expose identical read-only accessors for core invoice data.
- [ ] All fallible functions return a single top-level error or a small set of module errors.
- [x] FFI uses `FfiResult<T>` for fallible functions; no panics cross the boundary.
- [x] FFI exports include all accessors (totals, parties, validation response) and headers match Rust.
- [x] FFI constructors avoid long parameter lists; prefer config handles and setters.
- [x] FFI provides both string/bytes and `_file` helpers for CSR and invoice parsing.
- [x] FFI handle types are `#[repr(C)]` opaque structs; enums are `repr(i32)` with explicit discriminants.
- [x] Remove filesystem helpers where not essential (no file-based helpers outside CSR + invoice XML parse).
- [x] Remove custom XSD handling entirely (no `with_xsd_path`).
- [x] CLI `validate` uses bundled XSD only (no `--xsd-path` flag).
- [ ] Evaluate whether `Config` still adds value beyond `Environment` (keep only if extensibility is needed).

## Proposed Signature List (Core)
This list is intentionally minimal and string/bytes-only at the public boundary. Names reflect current API.

### config
```rust
pub enum EnvironmentType { NonProduction, Simulation, Production }
pub struct Config { ... }
impl Config {
    pub fn new(env: EnvironmentType) -> Self;
    pub fn env(&self) -> EnvironmentType;
}
```

### csr
```rust
pub struct CsrProperties { ... }
impl CsrProperties {
    pub fn new(...fields...) -> Result<Self, Error>;
    pub fn from_properties_str(s: &str) -> Result<Self, Error>;
    pub fn parse_csr_config(properties: &str) -> Result<Self, Error>;
    pub fn parse_csr_config_file(path: &Path) -> Result<Self, Error>;
}

pub struct SigningKey { ... }
impl SigningKey {
    pub fn generate() -> Self;
    pub fn from_der(bytes: &[u8]) -> Result<Self, Error>;
    pub fn from_pem(pem: &str) -> Result<Self, Error>;
    pub fn to_der(&self) -> Result<Vec<u8>, Error>;
    pub fn to_pem(&self) -> Result<String, Error>;
}

pub struct Csr { ... }
impl Csr {
    pub fn to_der(&self) -> Result<Vec<u8>, Error>;
    pub fn to_pem(&self) -> Result<String, Error>;
    pub fn to_base64(&self) -> Result<String, Error>;
    pub fn to_pem_base64(&self) -> Result<String, Error>;
}

impl CsrProperties {
    pub fn build(&self, key: &SigningKey, env: EnvironmentType) -> Result<Csr, Error>;
}
```

### invoice model
```rust
pub struct CountryCode(String);
pub struct CurrencyCode(String);
pub struct InvoiceTimestamp(String); // ZATCA ISO UTC: YYYY-MM-DDTHH:MM:SSZ

pub struct Address { ... }
pub struct VatId(String);
pub struct OtherId { ... }
pub struct InvoiceNote { ... }
pub struct Party { ... }
pub type Seller = Party;
pub type Buyer = Party;

pub enum InvoiceSubType { Standard, Simplified }
pub enum InvoiceType {
    Tax(InvoiceSubType),
    Prepayment(InvoiceSubType),
    CreditNote(InvoiceSubType, OriginalInvoiceRef, String),
    DebitNote(InvoiceSubType, OriginalInvoiceRef, String),
}

pub struct OriginalInvoiceRef { ... }
bitflags! { pub struct InvoiceFlags: u8 { ... } }

pub struct LineItem { ... }
pub struct InvoiceTotalsData { ... }
pub struct FinalizedInvoice { ... }
pub struct SignedInvoice { ... }
```

### invoice builder
```rust
pub struct InvoiceBuilder { ... }
impl InvoiceBuilder {
    pub fn new(invoice_type: InvoiceType) -> Self;
    pub fn set_id(&mut self, id: impl Into<String>) -> &mut Self;
    pub fn set_uuid(&mut self, uuid: impl Into<String>) -> &mut Self;
    pub fn set_issue_datetime(&mut self, issue_datetime: impl Into<String>) -> &mut Self;
    pub fn set_currency(&mut self, currency: impl Into<String>) -> &mut Self;
    pub fn set_previous_invoice_hash(&mut self, hash: impl Into<String>) -> &mut Self;
    pub fn set_invoice_counter(&mut self, counter: u64) -> &mut Self;
    pub fn set_seller(&mut self, seller: Seller) -> &mut Self;
    pub fn set_payment_means_code(&mut self, code: impl Into<String>) -> &mut Self;
    pub fn set_vat_category(&mut self, vat_category: VatCategory) -> &mut Self;
    pub fn set_buyer(&mut self, buyer: Buyer) -> &mut Self;
    pub fn set_note(&mut self, note: InvoiceNote) -> &mut Self;
    pub fn set_allowance(&mut self, reason: String, amount: f64) -> &mut Self;
    pub fn add_line_item(&mut self, item: LineItem) -> &mut Self;
    pub fn flags(&mut self, flags: InvoiceFlags) -> &mut Self;
    pub fn build(self) -> Result<FinalizedInvoice, Error>;
}
```

### invoice signing + XML
```rust
pub struct InvoiceSigner { ... }
impl InvoiceSigner {
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, Error>;
    pub fn from_der(cert_der: &[u8], key_der: &[u8]) -> Result<Self, Error>;
    pub fn sign(&self, invoice: FinalizedInvoice) -> Result<SignedInvoice, Error>;
    pub fn sign_xml(&self, xml: &str) -> Result<SignedInvoice, Error>;
}

pub fn invoice_hash_base64_from_xml(xml: &str) -> Result<String, Error>;

pub fn parse_finalized_invoice_xml(xml: &str) -> Result<FinalizedInvoice, Error>;
pub fn parse_finalized_invoice_xml_file(path: impl AsRef<Path>) -> Result<FinalizedInvoice, Error>;

pub fn parse_signed_invoice_xml(xml: &str) -> Result<SignedInvoice, Error>;
pub fn parse_signed_invoice_xml_file(path: impl AsRef<Path>) -> Result<SignedInvoice, Error>;

pub fn validate_xml_invoice(xml: &str, config: &Config) -> Result<(), Error>;
```

### api client
```rust
pub enum CsidScope { Compliance, Production }

pub struct CsidCredentials { ... }
pub struct ZatcaClient { ... }
impl ZatcaClient {
    pub fn new(config: Config) -> Result<Self, Error>;
    pub async fn check_invoice_compliance(
        &self,
        invoice: &SignedInvoice,
        creds: &CsidCredentials,
    ) -> Result<ValidationResponse, Error>;
    pub async fn report_simplified_invoice(
        &self,
        invoice: &SignedInvoice,
        creds: &CsidCredentials,
        clearance_status: bool,
        accept_language: Option<&str>,
    ) -> Result<ValidationResponse, Error>;
    pub async fn clear_standard_invoice(
        &self,
        invoice: &SignedInvoice,
        creds: &CsidCredentials,
        clearance_status: bool,
        accept_language: Option<&str>,
    ) -> Result<ValidationResponse, Error>;
    pub async fn post_csr_for_ccsid(&self, csr: &Csr, otp: &str) -> Result<CsidCredentials, Error>;
    pub async fn post_ccsid_for_pcsid(&self, creds: &CsidCredentials) -> Result<CsidCredentials, Error>;
    pub async fn renew_csid(&self, creds: &CsidCredentials, csr: &Csr, otp: &str, accept_language: Option<&str>)
        -> Result<CsidCredentials, Error>;
}
```

## Proposed Signature List (FFI)
Names are illustrative; exact naming follows `fatoora_` prefix rules. This list reflects the current layout.

### FFI types
```c
/* Opaque handles */
typedef struct FfiConfig FfiConfig;
typedef struct FfiInvoiceBuilder FfiInvoiceBuilder;
typedef struct FfiFinalizedInvoice FfiFinalizedInvoice;
typedef struct FfiSignedInvoice FfiSignedInvoice;
typedef struct FfiSigner FfiSigner;
typedef struct FfiCsrProperties FfiCsrProperties;
typedef struct FfiCsr FfiCsr;
typedef struct FfiSigningKey FfiSigningKey;
typedef struct FfiZatcaClient FfiZatcaClient;
typedef struct FfiCsidCompliance FfiCsidCompliance;
typedef struct FfiCsidProduction FfiCsidProduction;
typedef struct FfiAddress FfiAddress;
typedef struct FfiParty FfiParty;
typedef struct FfiVatId FfiVatId;
typedef struct FfiOtherId FfiOtherId;
typedef struct FfiInvoiceNote FfiInvoiceNote;
typedef struct FfiOriginalInvoiceRef FfiOriginalInvoiceRef;
typedef struct FfiValidationResponse FfiValidationResponse;
typedef struct FfiValidationResults FfiValidationResults;
typedef struct FfiValidationMessage FfiValidationMessage;

/* Value types */
typedef struct FfiString FfiString;
typedef struct FfiBytes FfiBytes;
typedef struct FfiBytesList FfiBytesList;

/* Enums */
typedef enum FfiEnvironment FfiEnvironment;
typedef enum FfiInvoiceTypeKind FfiInvoiceTypeKind;
typedef enum FfiInvoiceSubType FfiInvoiceSubType;
typedef enum FfiInvoiceFlag FfiInvoiceFlag;
typedef enum FfiVatCategory FfiVatCategory;
typedef enum FfiErrorKind FfiErrorKind;

/* Result wrappers (generated per type) */
typedef struct FfiResult_FfiString FfiResult_FfiString;
/* ...other FfiResult_* specializations... */
```

### config
```c
FfiConfig* fatoora_config_new(FfiEnvironment env);
void fatoora_config_free(FfiConfig*);
```

### csr + key
```c
FfiResult_FfiCsrProperties fatoora_csr_properties_from_str(const char* s);
FfiResult_FfiCsrProperties fatoora_csr_properties_parse_csr_config(const char* properties);
FfiResult_FfiCsrProperties fatoora_csr_properties_parse_csr_config_file(const char* path);

FfiResult_FfiSigningKey fatoora_signing_key_from_pem(const char* pem);
FfiResult_FfiSigningKey fatoora_signing_key_from_der(const uint8_t* der, size_t len);
FfiResult_FfiSigningKey fatoora_signing_key_generate(void);
FfiResult_FfiString fatoora_signing_key_to_pem(FfiSigningKey* key);

FfiResult_FfiCsr fatoora_csr_build(FfiCsrProperties* props, FfiSigningKey* key, FfiEnvironment env);

FfiResult_FfiString fatoora_csr_to_base64(FfiCsr* csr);
FfiResult_FfiString fatoora_csr_to_pem_base64(FfiCsr* csr);

void fatoora_csr_free(FfiCsr*);
void fatoora_signing_key_free(FfiSigningKey*);
```

### invoice builder
```c
FfiResult_FfiInvoiceBuilder fatoora_invoice_builder_new(
    FfiInvoiceTypeKind kind,
    FfiInvoiceSubType sub_type,
    const char* original_invoice_id,
    const char* original_invoice_uuid,
    const char* original_invoice_issue_date,
    const char* original_invoice_reason
);

FfiResult_bool fatoora_invoice_builder_set_id(FfiInvoiceBuilder*, const char* id);
FfiResult_bool fatoora_invoice_builder_set_uuid(FfiInvoiceBuilder*, const char* uuid);
FfiResult_bool fatoora_invoice_builder_set_issue_datetime(FfiInvoiceBuilder*, const char* issue_timestamp);
FfiResult_bool fatoora_invoice_builder_set_currency(FfiInvoiceBuilder*, const char* currency_code);
FfiResult_bool fatoora_invoice_builder_set_previous_hash(FfiInvoiceBuilder*, const char* hash);
FfiResult_bool fatoora_invoice_builder_set_invoice_counter(FfiInvoiceBuilder*, uint64_t counter);
FfiResult_bool fatoora_invoice_builder_set_payment_means_code(FfiInvoiceBuilder*, const char* code);
FfiResult_bool fatoora_invoice_builder_set_vat_category(FfiInvoiceBuilder*, FfiVatCategory vat_category);

FfiResult_bool fatoora_invoice_builder_set_seller(FfiInvoiceBuilder*, ...);
FfiResult_bool fatoora_invoice_builder_set_buyer(FfiInvoiceBuilder*, ...);
FfiResult_bool fatoora_invoice_builder_set_note(FfiInvoiceBuilder*, const char* language, const char* text);
FfiResult_bool fatoora_invoice_builder_set_allowance(FfiInvoiceBuilder*, const char* reason, double amount);
FfiResult_bool fatoora_invoice_builder_add_line_item(
    FfiInvoiceBuilder*,
    const char* description,
    double quantity,
    const char* unit_code,
    double unit_price,
    double vat_rate,
    FfiVatCategory vat_category
);

FfiResult_bool fatoora_invoice_builder_flags(FfiInvoiceBuilder*, uint8_t flags);
FfiResult_FfiFinalizedInvoice fatoora_invoice_builder_build(FfiInvoiceBuilder*);
void fatoora_invoice_builder_free(FfiInvoiceBuilder*);
```

### invoice accessors
```c
/* FinalizedInvoice core data accessors */
FfiResult_FfiString fatoora_invoice_id(FfiFinalizedInvoice*);
FfiResult_FfiString fatoora_invoice_uuid(FfiFinalizedInvoice*);
FfiResult_FfiString fatoora_invoice_issue_datetime(FfiFinalizedInvoice*);
FfiResult_FfiString fatoora_invoice_currency(FfiFinalizedInvoice*);
FfiResult_FfiString fatoora_invoice_previous_hash(FfiFinalizedInvoice*);
FfiResult_u64      fatoora_invoice_counter(FfiFinalizedInvoice*);
FfiResult_FfiString fatoora_invoice_payment_means_code(FfiFinalizedInvoice*);
FfiResult_FfiVatCategory fatoora_invoice_vat_category(FfiFinalizedInvoice*);
FfiResult_FfiString fatoora_invoice_allowance_reason(FfiFinalizedInvoice*);
FfiResult_f64      fatoora_invoice_level_charge(FfiFinalizedInvoice*);
FfiResult_f64      fatoora_invoice_level_discount(FfiFinalizedInvoice*);

FfiResult_u8       fatoora_invoice_flags(FfiFinalizedInvoice*);
FfiResult_FfiInvoiceTypeKind fatoora_invoice_type_kind(FfiFinalizedInvoice*);
FfiResult_FfiInvoiceSubType  fatoora_invoice_sub_type(FfiFinalizedInvoice*);
FfiResult_FfiOriginalInvoiceRef fatoora_invoice_original_ref(FfiFinalizedInvoice*);
FfiResult_FfiString fatoora_invoice_original_reason(FfiFinalizedInvoice*);

FfiResult_FfiParty fatoora_invoice_seller(FfiFinalizedInvoice*);
FfiResult_FfiParty fatoora_invoice_buyer(FfiFinalizedInvoice*);
FfiResult_FfiInvoiceNote fatoora_invoice_note(FfiFinalizedInvoice*);

/* Line items + totals are mirrored for signed/finalized */
FfiResult_u64  fatoora_invoice_line_item_count(FfiFinalizedInvoice*);
FfiResult_FfiString fatoora_invoice_line_item_description(FfiFinalizedInvoice*, uint64_t index);
FfiResult_FfiString fatoora_invoice_line_item_unit_code(FfiFinalizedInvoice*, uint64_t index);
FfiResult_f64  fatoora_invoice_line_item_quantity(FfiFinalizedInvoice*, uint64_t index);
FfiResult_f64  fatoora_invoice_line_item_unit_price(FfiFinalizedInvoice*, uint64_t index);
FfiResult_f64  fatoora_invoice_line_item_total_amount(FfiFinalizedInvoice*, uint64_t index);
FfiResult_f64  fatoora_invoice_line_item_vat_rate(FfiFinalizedInvoice*, uint64_t index);
FfiResult_f64  fatoora_invoice_line_item_vat_amount(FfiFinalizedInvoice*, uint64_t index);
FfiResult_u8   fatoora_invoice_line_item_vat_category(FfiFinalizedInvoice*, uint64_t index);

FfiResult_f64 fatoora_invoice_totals_tax_inclusive(FfiFinalizedInvoice*);
FfiResult_f64 fatoora_invoice_totals_tax_amount(FfiFinalizedInvoice*);
FfiResult_f64 fatoora_invoice_totals_line_extension(FfiFinalizedInvoice*);
FfiResult_f64 fatoora_invoice_totals_allowance_total(FfiFinalizedInvoice*);
FfiResult_f64 fatoora_invoice_totals_charge_total(FfiFinalizedInvoice*);
FfiResult_f64 fatoora_invoice_totals_taxable_amount(FfiFinalizedInvoice*);

FfiResult_FfiString fatoora_invoice_to_xml(FfiFinalizedInvoice*);
FfiResult_FfiString fatoora_invoice_hash_base64(FfiFinalizedInvoice*);
void fatoora_invoice_free(FfiFinalizedInvoice*);

/* SignedInvoice core data accessors (mirrors FinalizedInvoice) */
FfiResult_FfiString fatoora_signed_invoice_id(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_issue_datetime(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_currency(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_previous_hash(FfiSignedInvoice*);
FfiResult_u64      fatoora_signed_invoice_counter(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_payment_means_code(FfiSignedInvoice*);
FfiResult_FfiVatCategory fatoora_signed_invoice_vat_category(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_allowance_reason(FfiSignedInvoice*);
FfiResult_f64      fatoora_signed_invoice_level_charge(FfiSignedInvoice*);
FfiResult_f64      fatoora_signed_invoice_level_discount(FfiSignedInvoice*);

FfiResult_u8       fatoora_signed_invoice_flags(FfiSignedInvoice*);
FfiResult_FfiInvoiceTypeKind fatoora_signed_invoice_type_kind(FfiSignedInvoice*);
FfiResult_FfiInvoiceSubType  fatoora_signed_invoice_sub_type(FfiSignedInvoice*);
FfiResult_FfiOriginalInvoiceRef fatoora_signed_invoice_original_ref(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_original_reason(FfiSignedInvoice*);

FfiResult_FfiParty fatoora_signed_invoice_seller(FfiSignedInvoice*);
FfiResult_FfiParty fatoora_signed_invoice_buyer(FfiSignedInvoice*);
FfiResult_FfiInvoiceNote fatoora_signed_invoice_note(FfiSignedInvoice*);

FfiResult_u64  fatoora_signed_invoice_line_item_count(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_line_item_description(FfiSignedInvoice*, uint64_t index);
FfiResult_FfiString fatoora_signed_invoice_line_item_unit_code(FfiSignedInvoice*, uint64_t index);
FfiResult_f64  fatoora_signed_invoice_line_item_quantity(FfiSignedInvoice*, uint64_t index);
FfiResult_f64  fatoora_signed_invoice_line_item_unit_price(FfiSignedInvoice*, uint64_t index);
FfiResult_f64  fatoora_signed_invoice_line_item_total_amount(FfiSignedInvoice*, uint64_t index);
FfiResult_f64  fatoora_signed_invoice_line_item_vat_rate(FfiSignedInvoice*, uint64_t index);
FfiResult_f64  fatoora_signed_invoice_line_item_vat_amount(FfiSignedInvoice*, uint64_t index);
FfiResult_u8   fatoora_signed_invoice_line_item_vat_category(FfiSignedInvoice*, uint64_t index);

FfiResult_f64 fatoora_signed_invoice_totals_tax_inclusive(FfiSignedInvoice*);
FfiResult_f64 fatoora_signed_invoice_totals_tax_amount(FfiSignedInvoice*);
FfiResult_f64 fatoora_signed_invoice_totals_line_extension(FfiSignedInvoice*);
FfiResult_f64 fatoora_signed_invoice_totals_allowance_total(FfiSignedInvoice*);
FfiResult_f64 fatoora_signed_invoice_totals_charge_total(FfiSignedInvoice*);
FfiResult_f64 fatoora_signed_invoice_totals_taxable_amount(FfiSignedInvoice*);

/* Signed-only accessors */
FfiResult_FfiString fatoora_signed_invoice_xml(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_to_xml_base64(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_qr_code(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_uuid(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_hash(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_signature(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_public_key(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_cert_hash(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_signed_props_hash(FfiSignedInvoice*);
FfiResult_FfiString fatoora_signed_invoice_signing_time(FfiSignedInvoice*);

void fatoora_signed_invoice_free(FfiSignedInvoice*);
```

### signing + XML parse
```c
FfiResult_FfiSigner fatoora_signer_from_pem(const char* cert_pem, const char* key_pem);
FfiResult_FfiSigner fatoora_signer_from_der(const uint8_t* cert_der, size_t cert_len, const uint8_t* key_der, size_t key_len);

FfiResult_FfiSignedInvoice fatoora_invoice_sign(FfiFinalizedInvoice*, FfiSigner*);
FfiResult_FfiSignedInvoice fatoora_invoice_sign_xml(FfiSigner*, const char* xml);

FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml(const char* xml);
FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml_file(const char* path);
FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml(const char* xml);
FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml_file(const char* path);
```

### validation
```c
FfiResult_bool fatoora_validate_xml_invoice_from_str(FfiConfig*, const char* xml);
```

### api client
```c
FfiResult_FfiZatcaClient fatoora_zatca_client_new(FfiConfig*);

/* CSID handles (request_id is a UTF-8 string; empty string is the sentinel) */
FfiResult_FfiCsidCompliance fatoora_csid_compliance_new(
    FfiEnvironment env,
    const char* request_id,
    const char* token,
    const char* secret
);
FfiResult_FfiCsidProduction fatoora_csid_production_new(
    FfiEnvironment env,
    const char* request_id,
    const char* token,
    const char* secret
);

FfiResult_FfiValidationResponse fatoora_zatca_check_invoice_compliance(
    FfiZatcaClient*,
    FfiSignedInvoice*,
    FfiCsidCompliance*
);
FfiResult_FfiValidationResponse fatoora_zatca_report_simplified_invoice(
    FfiZatcaClient*,
    FfiSignedInvoice*,
    FfiCsidProduction*,
    bool clearance_status,
    const char* accept_language
);
FfiResult_FfiValidationResponse fatoora_zatca_clear_standard_invoice(
    FfiZatcaClient*,
    FfiSignedInvoice*,
    FfiCsidProduction*,
    bool clearance_status,
    const char* accept_language
);

FfiResult_FfiCsidCompliance fatoora_zatca_post_csr_for_ccsid(FfiZatcaClient*, FfiCsr*, const char* otp);
FfiResult_FfiCsidProduction fatoora_zatca_post_ccsid_for_pcsid(FfiZatcaClient*, FfiCsidCompliance*);
FfiResult_FfiCsidProduction fatoora_zatca_renew_csid(
    FfiZatcaClient*,
    FfiCsidProduction*,
    FfiCsr*,
    const char* otp,
    const char* accept_language
);

void fatoora_zatca_client_free(FfiZatcaClient*);
void fatoora_csid_compliance_free(FfiCsidCompliance*);
void fatoora_csid_production_free(FfiCsidProduction*);
```

## Issues / Inconsistencies / Improvements (Current)
### Resolved
- External types exposed in core public API are removed or wrapped.
- FFI header is in sync with Rust exports (totals, parties, validation response fields, invoice type getters).
- FFI invoice type getters return `FfiInvoiceTypeKind`/`FfiInvoiceSubType` and are exported in headers.
- Validation response accessors are present in headers.

### Remaining / Follow-ups
- Decide if `Config` remains a public type or if `EnvironmentType` alone is enough.
- Review and simplify error taxonomy for a smaller top-level error surface.
- Keep docs/examples aligned with current accessors (especially new invoice accessors for signed/finalized).
