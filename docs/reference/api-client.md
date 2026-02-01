# ZATCA API Client

HTTP client for the ZATCA endpoints, plus response models.

## Symbols

=== "Rust"
    - `ZatcaClient::new(config: Config) -> Result<ZatcaClient, ZatcaError>`
    - `ZatcaClient::post_csr_for_ccsid(csr: &Csr, otp: &str) -> Result<CsidCredentials<Compliance>, ZatcaError>`
    - `ZatcaClient::post_ccsid_for_pcsid(ccsid: &CsidCredentials<Compliance>) -> Result<CsidCredentials<Production>, ZatcaError>`
    - `ZatcaClient::renew_csid(pcsid: &CsidCredentials<Production>, csr: &Csr, otp: &str, accept_language: Option<&str>) -> Result<CsidCredentials<Production>, ZatcaError>`
    - `ZatcaClient::check_invoice_compliance(invoice: &SignedInvoice, credentials: &CsidCredentials<Compliance>) -> Result<ValidationResponse, ZatcaError>`
    - `ZatcaClient::report_simplified_invoice(invoice: &SignedInvoice, credentials: &CsidCredentials<Production>, clearance_status: bool, accept_language: Option<&str>) -> Result<ValidationResponse, ZatcaError>`
    - `ZatcaClient::clear_standard_invoice(invoice: &SignedInvoice, credentials: &CsidCredentials<Production>, clearance_status: bool, accept_language: Option<&str>) -> Result<ValidationResponse, ZatcaError>`
    - `CsidCredentials::new(env: EnvironmentType, request_id: Option<String>, token: impl Into<String>, secret: impl Into<String>) -> CsidCredentials<T>`
    - `CsidCredentials::env(&self) -> EnvironmentType`
    - `CsidCredentials::request_id(&self) -> Option<&str>`
    - `CsidCredentials::binary_security_token(&self) -> &str`
    - `CsidCredentials::secret(&self) -> &str`

=== "Python"
    - `ZatcaClient(config: Config)`
    - `ZatcaClient.post_csr_for_ccsid(csr: Csr, otp: str) -> CsidCompliance`
    - `ZatcaClient.post_ccsid_for_pcsid(ccsid: CsidCompliance) -> CsidProduction`
    - `ZatcaClient.renew_csid(pcsid: CsidProduction, csr: Csr, otp: str, accept_language: Optional[str]) -> CsidProduction`
    - `ZatcaClient.check_compliance(invoice: SignedInvoice, ccsid: CsidCompliance) -> ValidationResponse`
    - `ZatcaClient.report_simplified_invoice(invoice: SignedInvoice, pcsid: CsidProduction, clearance_status: bool, accept_language: Optional[str]) -> ValidationResponse`
    - `ZatcaClient.clear_standard_invoice(invoice: SignedInvoice, pcsid: CsidProduction, clearance_status: bool, accept_language: Optional[str]) -> ValidationResponse`
    - `CsidCompliance.new(env: Environment, token: str, secret: str, request_id: Optional[str] = None) -> CsidCompliance`
    - `CsidProduction.new(env: Environment, token: str, secret: str, request_id: Optional[str] = None) -> CsidProduction`
    - `CsidCompliance.env() -> Environment`, `CsidProduction.env() -> Environment`
    - `CsidCompliance.request_id() -> str`, `CsidProduction.request_id() -> str`
    - `CsidCompliance.token() -> str`, `CsidProduction.token() -> str`
    - `CsidCompliance.secret() -> str`, `CsidProduction.secret() -> str`

=== "C (FFI)"
    - `fatoora_zatca_client_new(config: FfiConfig*) -> FfiResult_FfiZatcaClient`
    - `fatoora_zatca_post_csr_for_ccsid(client: FfiZatcaClient*, csr: FfiCsr*, otp: const char*) -> FfiResult_FfiCsidCompliance`
    - `fatoora_zatca_post_ccsid_for_pcsid(client: FfiZatcaClient*, ccsid: FfiCsidCompliance*) -> FfiResult_FfiCsidProduction`
    - `fatoora_zatca_renew_csid(client: FfiZatcaClient*, pcsid: FfiCsidProduction*, csr: FfiCsr*, otp: const char*, accept_language: const char*) -> FfiResult_FfiCsidProduction`
    - `fatoora_zatca_check_compliance(client: FfiZatcaClient*, invoice: FfiSignedInvoice*, ccsid: FfiCsidCompliance*) -> FfiResult_FfiValidationResponse`
    - `fatoora_zatca_report_simplified_invoice(client: FfiZatcaClient*, invoice: FfiSignedInvoice*, pcsid: FfiCsidProduction*, clearance_status: bool, accept_language: const char*) -> FfiResult_FfiValidationResponse`
    - `fatoora_zatca_clear_standard_invoice(client: FfiZatcaClient*, invoice: FfiSignedInvoice*, pcsid: FfiCsidProduction*, clearance_status: bool, accept_language: const char*) -> FfiResult_FfiValidationResponse`
    - `fatoora_csid_compliance_new(env: FfiEnvironment, request_id: const char*, token: const char*, secret: const char*) -> FfiResult_FfiCsidCompliance`
    - `fatoora_csid_production_new(env: FfiEnvironment, request_id: const char*, token: const char*, secret: const char*) -> FfiResult_FfiCsidProduction`
    - `fatoora_csid_*_env(creds: FfiCsid*) -> FfiResult_FfiEnvironment`
    - `fatoora_csid_*_request_id(creds: FfiCsid*) -> FfiResult_FfiString`
    - `fatoora_csid_*_token(creds: FfiCsid*) -> FfiResult_FfiString`
    - `fatoora_csid_*_secret(creds: FfiCsid*) -> FfiResult_FfiString`

## Response types
- `ValidationResponse` exposes `validation_results()`, `reporting_status()`, `clearance_status()`,
  and QR status fields.
- `ValidationResults` exposes `info_messages()`, `warning_messages()`, `error_messages()`,
  and `status()`.
- `ValidationMessage` exposes `type`, `code`, `category`, `message`, `status` fields.
- `MessageList` normalizes info messages that may be `one`, `many`, or `empty`.
- `UnauthorizedResponse` and `ServerErrorResponse` provide structured error bodies.

## Errors
- `ZatcaError` is returned for HTTP failures, invalid responses, unauthorized/server errors, and
  client-state mismatches (environment, invoice type, etc.).

See also: [API Client Guide](../guides/api.md)
