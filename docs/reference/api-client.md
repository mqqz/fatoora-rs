# ZATCA API Client

HTTP client for the ZATCA endpoints, plus response models.

## Client

??? note "Create client"
    Create a ZATCA client from config.

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
        - `config`: environment config handle.

    !!! info "Returns"
        - `ZatcaClient`: configured client.

??? note "CSID flows"
    Issue and renew credentials.

    === "{{ lang.rust }}"
        ```rust
        ZatcaClient::post_csr_for_ccsid(csr: &Csr, otp: &str) -> Result<CsidCredentials<Compliance>, ZatcaError>
        ZatcaClient::post_ccsid_for_pcsid(ccsid: &CsidCredentials<Compliance>) -> Result<CsidCredentials<Production>, ZatcaError>
        ZatcaClient::renew_csid(pcsid: &CsidCredentials<Production>, csr: &Csr, otp: &str, accept_language: Option<&str>) -> Result<CsidCredentials<Production>, ZatcaError>
        ```

    === "{{ lang.python }}"
        ```python
        ZatcaClient.post_csr_for_ccsid(csr: Csr, otp: str) -> CsidCompliance
        ZatcaClient.post_ccsid_for_pcsid(ccsid: CsidCompliance) -> CsidProduction
        ZatcaClient.renew_csid(pcsid: CsidProduction, csr: Csr, otp: str, accept_language: Optional[str]) -> CsidProduction
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsidCompliance fatoora_zatca_post_csr_for_ccsid(FfiZatcaClient* client, FfiCsr* csr, const char* otp);
        FfiResult_FfiCsidProduction fatoora_zatca_post_ccsid_for_pcsid(FfiZatcaClient* client, FfiCsidCompliance* ccsid);
        FfiResult_FfiCsidProduction fatoora_zatca_renew_csid(FfiZatcaClient* client, FfiCsidProduction* pcsid, FfiCsr* csr, const char* otp, const char* accept_language);
        ```

    !!! info "Args"
        - `csr`: CSR object.
        - `otp`: one-time password from ZATCA portal.
        - `accept_language`: optional language header.

    !!! info "Returns"
        - `CsidCompliance` / `CsidProduction`: credential handles.

??? note "Invoice endpoints"
    Compliance check, reporting, and clearance.

    === "{{ lang.rust }}"
        ```rust
        ZatcaClient::check_invoice_compliance(invoice: &SignedInvoice, credentials: &CsidCredentials<Compliance>) -> Result<ValidationResponse, ZatcaError>
        ZatcaClient::report_simplified_invoice(invoice: &SignedInvoice, credentials: &CsidCredentials<Production>, clearance_status: bool, accept_language: Option<&str>) -> Result<ValidationResponse, ZatcaError>
        ZatcaClient::clear_standard_invoice(invoice: &SignedInvoice, credentials: &CsidCredentials<Production>, clearance_status: bool, accept_language: Option<&str>) -> Result<ValidationResponse, ZatcaError>
        ```

    === "{{ lang.python }}"
        ```python
        ZatcaClient.check_compliance(invoice: SignedInvoice, ccsid: CsidCompliance) -> ValidationResponse
        ZatcaClient.report_simplified_invoice(invoice: SignedInvoice, pcsid: CsidProduction, clearance_status: bool, accept_language: Optional[str]) -> ValidationResponse
        ZatcaClient.clear_standard_invoice(invoice: SignedInvoice, pcsid: CsidProduction, clearance_status: bool, accept_language: Optional[str]) -> ValidationResponse
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiValidationResponse fatoora_zatca_check_compliance(FfiZatcaClient* client, FfiSignedInvoice* invoice, FfiCsidCompliance* ccsid);
        FfiResult_FfiValidationResponse fatoora_zatca_report_simplified_invoice(FfiZatcaClient* client, FfiSignedInvoice* invoice, FfiCsidProduction* pcsid, bool clearance_status, const char* accept_language);
        FfiResult_FfiValidationResponse fatoora_zatca_clear_standard_invoice(FfiZatcaClient* client, FfiSignedInvoice* invoice, FfiCsidProduction* pcsid, bool clearance_status, const char* accept_language);
        ```

    !!! info "Args"
        - `invoice`: signed invoice handle.
        - `ccsid` / `pcsid`: compliance or production credentials.
        - `clearance_status`: request clearance status in response.
        - `accept_language`: optional language header.

    !!! info "Returns"
        - `ValidationResponse`: structured response with statuses and messages.

## Credentials

??? note "Credential helpers"
    Build and inspect credential handles.

    === "{{ lang.rust }}"
        ```rust
        CsidCredentials::new(env: EnvironmentType, request_id: Option<String>, token: impl Into<String>, secret: impl Into<String>) -> CsidCredentials<T>
        CsidCredentials::env(&self) -> EnvironmentType
        CsidCredentials::request_id(&self) -> Option<&str>
        CsidCredentials::binary_security_token(&self) -> &str
        CsidCredentials::secret(&self) -> &str
        ```

    === "{{ lang.python }}"
        ```python
        CsidCompliance.new(env: Environment, token: str, secret: str, request_id: Optional[str] = None) -> CsidCompliance
        CsidProduction.new(env: Environment, token: str, secret: str, request_id: Optional[str] = None) -> CsidProduction
        CsidCompliance.env() -> Environment
        CsidCompliance.request_id() -> str
        CsidCompliance.token() -> str
        CsidCompliance.secret() -> str
        ```

    === "{{ lang.c }}"
        ```c
        FfiResult_FfiCsidCompliance fatoora_csid_compliance_new(FfiEnvironment env, const char* request_id, const char* token, const char* secret);
        FfiResult_FfiCsidProduction fatoora_csid_production_new(FfiEnvironment env, const char* request_id, const char* token, const char* secret);
        FfiResult_FfiEnvironment fatoora_csid_compliance_env(FfiCsidCompliance* creds);
        FfiResult_FfiString fatoora_csid_compliance_request_id(FfiCsidCompliance* creds);
        FfiResult_FfiString fatoora_csid_compliance_token(FfiCsidCompliance* creds);
        FfiResult_FfiString fatoora_csid_compliance_secret(FfiCsidCompliance* creds);
        FfiResult_FfiEnvironment fatoora_csid_production_env(FfiCsidProduction* creds);
        FfiResult_FfiString fatoora_csid_production_request_id(FfiCsidProduction* creds);
        FfiResult_FfiString fatoora_csid_production_token(FfiCsidProduction* creds);
        FfiResult_FfiString fatoora_csid_production_secret(FfiCsidProduction* creds);
        ```

    !!! info "Args"
        - `env`: target environment.
        - `token` / `secret`: credential values.
        - `request_id`: optional request ID.

    !!! info "Returns"
        - credential handles and field accessors.

## Response Types

!!! note "Response shapes"
    - `ValidationResponse` exposes validation_results(), reporting_status(), clearance_status(), and QR status fields.
    - `ValidationResults` exposes info_messages(), warning_messages(), error_messages(), and status().
    - `ValidationMessage` exposes type, code, category, message, status fields.
    - `MessageList` normalizes info messages that may be one, many, or empty.
    - `UnauthorizedResponse` and `ServerErrorResponse` provide structured error bodies.

!!! warning "Errors"
    - `ZatcaError` is returned for HTTP failures, invalid responses, unauthorized/server errors, and client-state mismatches (environment, invoice type, etc.).

See also: [API Client Guide](../guides/api.md)
