# ZATCA API Client

See [C and C++ bindings](bindings/c.md) for ownership rules and text output.
The declarations below come from the generated headers. C++ exposes the same types
in namespace `fatoora` through `fatoora/Type.hpp` headers.

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
        #include "ZatcaClient.h"

        fatoora_ZatcaClient_create_result fatoora_ZatcaClient_create(const Config* config);
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
        #include "ZatcaClient.h"

        fatoora_ZatcaClient_post_csr_for_ccsid_result fatoora_ZatcaClient_post_csr_for_ccsid(const ZatcaClient* self, const Csr* csr, DiplomatStringView otp);
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
        #include "ZatcaClient.h"

        fatoora_ZatcaClient_post_ccsid_for_pcsid_result fatoora_ZatcaClient_post_ccsid_for_pcsid(const ZatcaClient* self, const CsidCompliance* credentials);
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
        #include "ZatcaClient.h"

        fatoora_ZatcaClient_renew_csid_result fatoora_ZatcaClient_renew_csid(const ZatcaClient* self, const CsidProduction* credentials, const Csr* csr, DiplomatStringView otp, OptionStringView accept_language);
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
        #include "ZatcaClient.h"

        fatoora_ZatcaClient_check_invoice_compliance_result fatoora_ZatcaClient_check_invoice_compliance(const ZatcaClient* self, const SignedInvoice* invoice, const CsidCompliance* credentials);
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
        #include "ZatcaClient.h"

        fatoora_ZatcaClient_report_simplified_invoice_result fatoora_ZatcaClient_report_simplified_invoice(const ZatcaClient* self, const SignedInvoice* invoice, const CsidProduction* credentials, bool clearance_status, OptionStringView accept_language);
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
        #include "ZatcaClient.h"

        fatoora_ZatcaClient_clear_standard_invoice_result fatoora_ZatcaClient_clear_standard_invoice(const ZatcaClient* self, const SignedInvoice* invoice, const CsidProduction* credentials, bool clearance_status, OptionStringView accept_language);
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
        #include "CsidCompliance.h"
        #include "CsidProduction.h"

        fatoora_CsidCompliance_create_result fatoora_CsidCompliance_create(uint8_t environment, OptionStringView request_id, DiplomatStringView token, DiplomatStringView secret);
        fatoora_CsidProduction_create_result fatoora_CsidProduction_create(uint8_t environment, OptionStringView request_id, DiplomatStringView token, DiplomatStringView secret);
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
        #include "CsidCompliance.h"
        #include "CsidProduction.h"

        uint8_t fatoora_CsidCompliance_env(const CsidCompliance* self);
        uint8_t fatoora_CsidProduction_env(const CsidProduction* self);
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
        #include "CsidCompliance.h"
        #include "CsidProduction.h"

        fatoora_CsidCompliance_request_id_result fatoora_CsidCompliance_request_id(const CsidCompliance* self);
        fatoora_CsidProduction_request_id_result fatoora_CsidProduction_request_id(const CsidProduction* self);
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
        #include "CsidCompliance.h"
        #include "CsidProduction.h"

        fatoora_CsidCompliance_binary_security_token_result fatoora_CsidCompliance_binary_security_token(const CsidCompliance* self, DiplomatWrite* write);
        fatoora_CsidProduction_binary_security_token_result fatoora_CsidProduction_binary_security_token(const CsidProduction* self, DiplomatWrite* write);
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
        #include "CsidCompliance.h"
        #include "CsidProduction.h"

        fatoora_CsidCompliance_secret_result fatoora_CsidCompliance_secret(const CsidCompliance* self, DiplomatWrite* write);
        fatoora_CsidProduction_secret_result fatoora_CsidProduction_secret(const CsidProduction* self, DiplomatWrite* write);
        ```

## Invoice response contract

This contract applies to reporting, clearance, and invoice compliance methods.
`Ok` (or a Python return value) means HTTP 2xx with a decoded validation body.
Non-2xx responses, including 400 and 409, return errors. Successful HTTP status
alone does not establish invoice acceptance.

| Accessor | Rust | Python | C result value |
| --- | --- | --- | --- |
| `http_status()` | `Option<u16>` | `Optional[int]` | `uint16_t`, zero if unavailable |
| `outcome()` | `InvoiceOutcome` | `InvoiceOutcome` | `uint8_t`: 0 unknown, 1 accepted, 2 rejected |
| `ensure_accepted()` | `Result<(), ZatcaError>` | returns `None` or raises `ApiError` | true or an error |
| `cleared_invoice_base64()` | `Option<&str>` | `Optional[str]` | copied string; null if absent |
| `cleared_invoice_xml()` | `Result<Option<String>, ZatcaError>` | `Optional[str]` or `ParseError` | copied decoded string or error; null if absent |

C accessor names start with `fatoora_ValidationResponse_`. Text getters write to
`DiplomatWrite`, or return optional owned `Text` objects. Destroy owned text with
`fatoora_Text_destroy`; buffer writers use `diplomat_buffer_write_destroy`.
Response children are owned copies and survive destruction of the response.
A present but empty base64 field stays an empty string and fails decoding.

Outcome uses the endpoint actually invoked: `REPORTED`/`NOT_REPORTED` for
reporting, `CLEARED`/`NOT_CLEARED` for clearance, and `PASS` or `WARNING`/`ERROR`
for compliance. A positive status alongside validation errors is `Unknown`.
Unknown or missing endpoint status also yields `Unknown`. Standalone JSON
serialization omits HTTP/operation metadata; deserializing a body yields no HTTP
status and an unknown outcome, even if the JSON includes metadata-like fields.
`ensure_accepted()` fails for both rejected and unknown outcomes and retains the
response in `ZatcaError::NotAccepted`.

A compliance pass establishes only the result of that check. Cleared XML decoding
preserves the returned text and performs neither XML parsing nor signature
verification. Missing cleared XML is independent of the acceptance outcome.

### Duplicate submissions and redirects

Reporting HTTP 409 can mean that the same invoice hash was already reported;
this submission returns an error without asserting that the earlier invoice was
rejected. Duplicate clearance HTTP 208 follows the successful-response path and
can carry the cleared invoice. See the [Fatoora Development Team announcement](https://zatca1.discourse.group/t/deployment-notification-duplication-check-response-codes-208-and-409/7954).

The client does not follow HTTP redirects. A clearance-disabled 303 is exposed
as a structured response error; callers decide what to do next. This change does
not add automatic reporting of standard invoices. See the [ZATCA developer manual](https://www.zatca.gov.sa/en/E-Invoicing/SystemsDevelopers/ComplianceEnablementToolbox/Documents/Developer%20Portal%20User%20Manual.pdf).

Credential endpoints keep their existing response rules, including the wrapped
HTTP 428 renewal response.

### Migration

Code that previously handled 400/409 through `Ok(ValidationResponse)` must now
handle `ZatcaError::Response`, or `ApiError` in Python. Invoice HTTP 401 still
classifies as Unauthorized but now uses the status-preserving `Response` variant.
Other non-2xx invoice responses classify as Api. Successful HTTP responses with
malformed bodies classify as Parse; failed body reads classify as Network and
retain the received status. Rust callers can inspect `ZatcaError::http_status()`
and `HttpResponseError::body()` / `validation_response()`.

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
