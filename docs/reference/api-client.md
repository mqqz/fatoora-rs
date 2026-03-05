# ZATCA API Client

The HTTP client is the main way to contact ZATCA's official fatoora platform API.
Please do read the [ZATCA Official API Gateway](https://sandbox.zatca.gov.sa/IntegrationSandbox) 
for more details.

## ZatcaClient

### `new`

???+ note "Create client"

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

### `post_csr_for_ccsid`

???+ note "Issue compliance CSID"

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

### `post_ccsid_for_pcsid`

???+ note "Issue production CSID"

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

### `renew_csid`

???+ note "Renew production CSID"

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

### `check_invoice_compliance`

???+ note "Check invoice compliance"

    === "{{ lang.rust }}"
        ```rust
        ZatcaClient::check_invoice_compliance(invoice: &SignedInvoice, credentials: &CsidCredentials<Compliance>) -> Result<ValidationResponse, ZatcaError>
        ```

    === "{{ lang.python }}"
        ```python
        ZatcaClient.check_invoice_compliance(invoice: SignedInvoice, ccsid: CsidCompliance) -> ValidationResponse
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiValidationResponse fatoora_zatca_check_invoice_compliance(FfiZatcaClient* client, FfiSignedInvoice* invoice, FfiCsidCompliance* ccsid);
        ```

### `report_simplified_invoice`

???+ note "Report simplified invoice"

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

### `clear_standard_invoice`

???+ note "Clear standard invoice"

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

## CsidCredentials / CsidCompliance / CsidProduction

### `new`

???+ note "Create credential handle"

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

### `env`

???+ note "Read credential environment"

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

### `request_id`

???+ note "Read optional request id"

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

### `binary_security_token`

???+ note "Read token"

    === "{{ lang.rust }}"
        ```rust
        CsidCredentials::binary_security_token(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        CsidCompliance.binary_security_token() -> str
        CsidProduction.binary_security_token() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiString fatoora_csid_compliance_binary_security_token(FfiCsidCompliance* creds);
        FfiResult_FfiString fatoora_csid_production_binary_security_token(FfiCsidProduction* creds);
        ```

### `secret`

???+ note "Read credential secret"

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
