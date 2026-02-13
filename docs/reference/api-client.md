# ZATCA API Client

HTTP client for the ZATCA endpoints, plus response models.

## ZatcaClient

### new

??? note "Create client"

    === "{{ lang.rust }}"
        ```rust
        ZatcaClient::new(config: Config) -> Result<ZatcaClient, ZatcaError>
        ```

    === "{{ lang.python }}"
        ```python
        ZatcaClient(config: Config)
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiZatcaClient fatoora_zatca_client_new(FfiConfig* config);
        ```

    !!! info "Args"
        - `config` (`Config` / `FfiConfig*`): environment config.

    !!! info "Returns"
        - Rust: `Result<ZatcaClient, ZatcaError>`.
        - Python: `ZatcaClient`.
        - C: `FfiResult_FfiZatcaClient`.

### post_csr_for_ccsid

??? note "Issue compliance CSID"

    === "{{ lang.rust }}"
        ```rust
        ZatcaClient::post_csr_for_ccsid(csr: &Csr, otp: &str) -> Result<CsidCredentials<Compliance>, ZatcaError>
        ```

    === "{{ lang.python }}"
        ```python
        ZatcaClient.post_csr_for_ccsid(csr: Csr, otp: str) -> CsidCompliance
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsidCompliance fatoora_zatca_post_csr_for_ccsid(FfiZatcaClient* client, FfiCsr* csr, const char* otp);
        ```

    !!! info "Args"
        - `csr` (`&Csr` / `Csr` / `FfiCsr*`): CSR object.
        - `otp` (`&str` / `str` / `const char*`): one-time password from ZATCA portal.

    !!! info "Returns"
        - Rust: `Result<CsidCredentials<Compliance>, ZatcaError>`.
        - Python: `CsidCompliance`.
        - C: `FfiResult_FfiCsidCompliance`.

### post_ccsid_for_pcsid

??? note "Issue production CSID"

    === "{{ lang.rust }}"
        ```rust
        ZatcaClient::post_ccsid_for_pcsid(ccsid: &CsidCredentials<Compliance>) -> Result<CsidCredentials<Production>, ZatcaError>
        ```

    === "{{ lang.python }}"
        ```python
        ZatcaClient.post_ccsid_for_pcsid(ccsid: CsidCompliance) -> CsidProduction
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsidProduction fatoora_zatca_post_ccsid_for_pcsid(FfiZatcaClient* client, FfiCsidCompliance* ccsid);
        ```

    !!! info "Args"
        - `ccsid` (`&CsidCredentials<Compliance>` / `CsidCompliance` / `FfiCsidCompliance*`): compliance credentials.

    !!! info "Returns"
        - Rust: `Result<CsidCredentials<Production>, ZatcaError>`.
        - Python: `CsidProduction`.
        - C: `FfiResult_FfiCsidProduction`.

### renew_csid

??? note "Renew production CSID"

    === "{{ lang.rust }}"
        ```rust
        ZatcaClient::renew_csid(pcsid: &CsidCredentials<Production>, csr: &Csr, otp: &str, accept_language: Option<&str>) -> Result<CsidCredentials<Production>, ZatcaError>
        ```

    === "{{ lang.python }}"
        ```python
        ZatcaClient.renew_csid(pcsid: CsidProduction, csr: Csr, otp: str, accept_language: Optional[str]) -> CsidProduction
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsidProduction fatoora_zatca_renew_csid(FfiZatcaClient* client, FfiCsidProduction* pcsid, FfiCsr* csr, const char* otp, const char* accept_language);
        ```

    !!! info "Args"
        - `pcsid` (`&CsidCredentials<Production>` / `CsidProduction` / `FfiCsidProduction*`): production credentials.
        - `csr` (`&Csr` / `Csr` / `FfiCsr*`): CSR object.
        - `otp` (`&str` / `str` / `const char*`): one-time password.
        - `accept_language` (`Option<&str>` / `Optional[str]` / `const char*`): optional language header.

    !!! info "Returns"
        - Rust: `Result<CsidCredentials<Production>, ZatcaError>`.
        - Python: `CsidProduction`.
        - C: `FfiResult_FfiCsidProduction`.

### check_invoice_compliance / check_compliance

??? note "Check invoice compliance"

    === "{{ lang.rust }}"
        ```rust
        ZatcaClient::check_invoice_compliance(invoice: &SignedInvoice, credentials: &CsidCredentials<Compliance>) -> Result<ValidationResponse, ZatcaError>
        ```

    === "{{ lang.python }}"
        ```python
        ZatcaClient.check_compliance(invoice: SignedInvoice, ccsid: CsidCompliance) -> ValidationResponse
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiValidationResponse fatoora_zatca_check_compliance(FfiZatcaClient* client, FfiSignedInvoice* invoice, FfiCsidCompliance* ccsid);
        ```

    !!! info "Args"
        - `invoice` (`&SignedInvoice` / `SignedInvoice` / `FfiSignedInvoice*`): signed invoice.
        - `credentials` / `ccsid` (`CsidCredentials<Compliance>` / `CsidCompliance` / `FfiCsidCompliance*`): compliance credentials.

    !!! info "Returns"
        - Rust: `Result<ValidationResponse, ZatcaError>`.
        - Python: `ValidationResponse`.
        - C: `FfiResult_FfiValidationResponse`.

### report_simplified_invoice

??? note "Report simplified invoice"

    === "{{ lang.rust }}"
        ```rust
        ZatcaClient::report_simplified_invoice(invoice: &SignedInvoice, credentials: &CsidCredentials<Production>, clearance_status: bool, accept_language: Option<&str>) -> Result<ValidationResponse, ZatcaError>
        ```

    === "{{ lang.python }}"
        ```python
        ZatcaClient.report_simplified_invoice(invoice: SignedInvoice, pcsid: CsidProduction, clearance_status: bool, accept_language: Optional[str]) -> ValidationResponse
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiValidationResponse fatoora_zatca_report_simplified_invoice(FfiZatcaClient* client, FfiSignedInvoice* invoice, FfiCsidProduction* pcsid, bool clearance_status, const char* accept_language);
        ```

    !!! info "Args"
        - `invoice` (`&SignedInvoice` / `SignedInvoice` / `FfiSignedInvoice*`): signed invoice.
        - `credentials` / `pcsid` (`CsidCredentials<Production>` / `CsidProduction` / `FfiCsidProduction*`): production credentials.
        - `clearance_status` (`bool`): include clearance status.
        - `accept_language` (`Option<&str>` / `Optional[str]` / `const char*`): optional language header.

    !!! info "Returns"
        - Rust: `Result<ValidationResponse, ZatcaError>`.
        - Python: `ValidationResponse`.
        - C: `FfiResult_FfiValidationResponse`.

### clear_standard_invoice

??? note "Clear standard invoice"

    === "{{ lang.rust }}"
        ```rust
        ZatcaClient::clear_standard_invoice(invoice: &SignedInvoice, credentials: &CsidCredentials<Production>, clearance_status: bool, accept_language: Option<&str>) -> Result<ValidationResponse, ZatcaError>
        ```

    === "{{ lang.python }}"
        ```python
        ZatcaClient.clear_standard_invoice(invoice: SignedInvoice, pcsid: CsidProduction, clearance_status: bool, accept_language: Optional[str]) -> ValidationResponse
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiValidationResponse fatoora_zatca_clear_standard_invoice(FfiZatcaClient* client, FfiSignedInvoice* invoice, FfiCsidProduction* pcsid, bool clearance_status, const char* accept_language);
        ```

    !!! info "Args"
        - `invoice` (`&SignedInvoice` / `SignedInvoice` / `FfiSignedInvoice*`): signed invoice.
        - `credentials` / `pcsid` (`CsidCredentials<Production>` / `CsidProduction` / `FfiCsidProduction*`): production credentials.
        - `clearance_status` (`bool`): include clearance status.
        - `accept_language` (`Option<&str>` / `Optional[str]` / `const char*`): optional language header.

    !!! info "Returns"
        - Rust: `Result<ValidationResponse, ZatcaError>`.
        - Python: `ValidationResponse`.
        - C: `FfiResult_FfiValidationResponse`.

## CsidCredentials / CsidCompliance / CsidProduction

### new

??? note "Create credential handle"

    === "{{ lang.rust }}"
        ```rust
        CsidCredentials::new(env: EnvironmentType, request_id: Option<String>, token: impl Into<String>, secret: impl Into<String>) -> CsidCredentials<T>
        ```

    === "{{ lang.python }}"
        ```python
        CsidCompliance.new(env: Environment, token: str, secret: str, request_id: Optional[str] = None) -> CsidCompliance
        CsidProduction.new(env: Environment, token: str, secret: str, request_id: Optional[str] = None) -> CsidProduction
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsidCompliance fatoora_csid_compliance_new(FfiEnvironment env, const char* request_id, const char* token, const char* secret);
        FfiResult_FfiCsidProduction fatoora_csid_production_new(FfiEnvironment env, const char* request_id, const char* token, const char* secret);
        ```

    !!! info "Args"
        - `env` (`EnvironmentType` / `Environment` / `FfiEnvironment`): target environment.
        - `request_id` (`Option<String>` / `Optional[str]` / `const char*`): optional request id.
        - `token` (`String` / `str` / `const char*`): binary security token.
        - `secret` (`String` / `str` / `const char*`): shared secret.

    !!! info "Returns"
        - Rust: `CsidCredentials<T>`.
        - Python: `CsidCompliance` or `CsidProduction`.
        - C: `FfiResult_FfiCsidCompliance` or `FfiResult_FfiCsidProduction`.

### env

??? note "Read credential environment"

    === "{{ lang.rust }}"
        ```rust
        CsidCredentials::env(&self) -> EnvironmentType
        ```

    === "{{ lang.python }}"
        ```python
        CsidCompliance.env() -> Environment
        CsidProduction.env() -> Environment
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiEnvironment fatoora_csid_compliance_env(FfiCsidCompliance* creds);
        FfiResult_FfiEnvironment fatoora_csid_production_env(FfiCsidProduction* creds);
        ```

    !!! info "Returns"
        - Rust: `EnvironmentType`.
        - Python: `Environment`.
        - C: `FfiResult_FfiEnvironment`.

### request_id

??? note "Read optional request id"

    === "{{ lang.rust }}"
        ```rust
        CsidCredentials::request_id(&self) -> Option<&str>
        ```

    === "{{ lang.python }}"
        ```python
        CsidCompliance.request_id() -> str
        CsidProduction.request_id() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_csid_compliance_request_id(FfiCsidCompliance* creds);
        FfiResult_FfiString fatoora_csid_production_request_id(FfiCsidProduction* creds);
        ```

    !!! info "Returns"
        - Rust: `Option<&str>`.
        - Python: `str`.
        - C: `FfiResult_FfiString`.

### binary_security_token / token

??? note "Read token"

    === "{{ lang.rust }}"
        ```rust
        CsidCredentials::binary_security_token(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        CsidCompliance.token() -> str
        CsidProduction.token() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_csid_compliance_token(FfiCsidCompliance* creds);
        FfiResult_FfiString fatoora_csid_production_token(FfiCsidProduction* creds);
        ```

    !!! info "Returns"
        - Rust: `&str`.
        - Python: `str`.
        - C: `FfiResult_FfiString`.

### secret

??? note "Read credential secret"

    === "{{ lang.rust }}"
        ```rust
        CsidCredentials::secret(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        CsidCompliance.secret() -> str
        CsidProduction.secret() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_csid_compliance_secret(FfiCsidCompliance* creds);
        FfiResult_FfiString fatoora_csid_production_secret(FfiCsidProduction* creds);
        ```

    !!! info "Returns"
        - Rust: `&str`.
        - Python: `str`.
        - C: `FfiResult_FfiString`.

## Response Types

!!! note "Response shapes"
    - `ValidationResponse` exposes `validation_results()`, `reporting_status()`, `clearance_status()`, and QR status fields.
    - `ValidationResults` exposes `info_messages()`, `warning_messages()`, `error_messages()`, and `status()`.
    - `ValidationMessage` exposes type, code, category, message, and status fields.
    - `MessageList` normalizes info messages that may be one, many, or empty.
    - `UnauthorizedResponse` and `ServerErrorResponse` provide structured error bodies.

## Errors

!!! warning "Errors"
    - `ZatcaError` is returned for HTTP failures, invalid responses, unauthorized/server errors, and client-state mismatches (environment, invoice type, etc.).

See also: [API Client Guide](../guides/api.md)
