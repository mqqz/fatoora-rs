---
title: ZATCA API Client and Response Reference
description: Reference for ZATCA credentials, invoice compliance, reporting, and clearance. Find method inputs, return values, response fields, acceptance checks, and custom transport options.
---

# ZATCA API client

The API client requests credentials and submits signed invoices to the selected
[environment](configuration.md). For a runnable integration, start with the
[API guide](../guides/api.md). This reference describes inputs, returned data, and
how to distinguish a completed request from an accepted invoice.

## Choose an operation

| Operation | Required input | Returns | Behavior |
| --- | --- | --- | --- |
| Issue compliance credentials | CSR and OTP | Compliance credentials (CCSID) | Sends the CSR as Base64-encoded PEM. |
| Issue production credentials | Compliance credentials with a request ID | Production credentials (PCSID) | Uses the compliance request ID to request production credentials. |
| Renew production credentials | Existing production credentials, new CSR, OTP, response language | Production credentials | Submits a renewal request. |
| Check invoice compliance | Signed invoice and compliance credentials | Validation response | Checks the invoice; a passing check does not establish reporting or clearance. |
| Report a simplified invoice | Signed simplified invoice, production credentials, clearance flag, response language | Validation response | Rejects standard invoices before sending. |
| Clear a standard invoice | Signed standard invoice, production credentials, clearance flag, response language | Validation response | Rejects simplified invoices before sending. |

Credentials must match the client's environment. Production credentials describe
the credential scope; they can belong to a test environment. The credential
constructor stores supplied values; it does not authenticate them or obtain a
certificate. Preserve the request ID returned during compliance onboarding.

## Input values

| Input | Expected value | Notes |
| --- | --- | --- |
| Configuration | Selected environment | Used for endpoints and credential environment checks. |
| CSR | Parsed or generated certificate signing request | See [CSR reference](csr.md). Supply the matching private key separately when signing invoices. |
| OTP | Text supplied for the onboarding or renewal operation | Sent in the OTP header. Invalid HTTP-header characters fail before transport. |
| Token | Binary security token returned by ZATCA | Used with the secret for HTTP Basic authentication. |
| Secret | Credential secret returned by ZATCA | Keep credentials out of logs. |
| Request ID | Optional text from credential issuance | Required to request production credentials from compliance credentials. |
| Invoice | Signed invoice object | The client sends its hash, UUID, and Base64 XML. |
| Clearance flag | Boolean | Sends `Clearance-Status: 1` when true, `0` when false. It does not change the selected operation. |
| Response language | `ar`, `en`, or omitted | Only the exact value `ar` selects Arabic; every other value sends English. |

## Interpret an invoice response

A successful HTTP status means that a response body was decoded. **Check acceptance
before treating an invoice as reported or cleared.** The acceptance helper fails
for both rejected and unknown outcomes.

| Invoked operation | Accepted status | Rejected status |
| --- | --- | --- |
| Reporting | `REPORTED` | `NOT_REPORTED` |
| Clearance | `CLEARED` | `NOT_CLEARED` |
| Compliance | Validation status `PASS` or `WARNING` | Validation status `ERROR` |

Missing or unrecognized endpoint status produces an unknown outcome. A positive
status accompanied by validation errors also produces an unknown outcome.
Warnings alone do not prevent acceptance. Only the status for the operation
actually invoked determines its outcome.

| Returned field | Value | Meaning |
| --- | --- | --- |
| HTTP status | Optional integer | Actual response status, when attached by the client. |
| Outcome | Accepted, rejected, or unknown | Classification for the invoked operation. |
| Validation results | Result object | Contains message collections and optional overall status. |
| Reporting / clearance status | Optional text | Raw gateway status for each operation. |
| Seller / buyer QR status | Optional text | Raw QR status returned by the gateway. |
| Cleared invoice Base64 | Optional text | Exact encoded invoice returned by clearance. |
| Cleared invoice XML | Optional decoded text | Preserves returned text; does not parse XML or verify its signature. |

Missing cleared XML is independent of acceptance. A present empty Base64 value,
invalid Base64, NUL bytes, or invalid UTF-8 fails decoding.

Validation results contain information, warning, and error message collections,
which can be empty, plus an optional status. Each message has optional type, code,
category, message text, and status fields. Handle missing fields instead of
assuming that every response contains a complete diagnostic.

## HTTP failures and custom transport

Invoice operations treat every non-2xx response as an error, including 400 and
409. A duplicate-reporting 409 does not establish that an earlier submission was
rejected. A 208 clearance response follows the successful-response path and still
requires an acceptance check. Redirects are not followed; a 303 does not trigger
automatic reporting. A malformed successful body is a decoding error, and a failed
body read is a transport error.

Credential issuance requires a successful response. Renewal additionally supports
the gateway's 428 renewal response when it contains a decodable credential body.

Where exposed, prepared requests let you use your own HTTP transport. Preparing
performs input checks and builds an owned request without sending it. Send its
method, URL, headers, and body, then pass the actual HTTP status and response bytes
to its decoder. Headers contain credentials. The decoder preserves the operation
context needed for acceptance checks. Keep redirects disabled in custom transports.

<span id="zatcaclient"></span>
<span id="new"></span>
<span id="post_csr_for_ccsid"></span>
<span id="post_ccsid_for_pcsid"></span>
<span id="renew_csid"></span>
<span id="check_invoice_compliance"></span>
<span id="report_simplified_invoice"></span>
<span id="clear_standard_invoice"></span>
<span id="csidcredentials-csidcompliance-csidproduction"></span>
<span id="env"></span>
<span id="request_id"></span>
<span id="binary_security_token"></span>
<span id="secret"></span>
<span id="invoice-response-contract"></span>
<span id="duplicate-submissions-and-redirects"></span>
<span id="response-types"></span>
<span id="errors"></span>

<span id="new_1"></span>

## Language reference

=== "Rust"
    Import client, credential, and response types from `fatoora_core::api`.
    `ZatcaClient::new(config: Config)` returns `Result<ZatcaClient, ZatcaError>`.
    HTTP methods are async; call them with `.await`. Inputs below are borrowed.

    **HTTP operations**

    | Method on `client` | Returns after `.await` |
    | --- | --- |
    | `post_csr_for_ccsid(csr: &Csr, otp: &str)` | `Result<CsidCredentials<Compliance>, ZatcaError>` |
    | `post_ccsid_for_pcsid(ccsid: &CsidCredentials<Compliance>)` | `Result<CsidCredentials<Production>, ZatcaError>` |
    | `renew_csid(pcsid: &CsidCredentials<Production>, csr: &Csr, otp: &str, accept_language: Option<&str>)` | `Result<CsidCredentials<Production>, ZatcaError>` |
    | `check_invoice_compliance(invoice: &SignedInvoice, credentials: &CsidCredentials<Compliance>)` | `Result<ValidationResponse, ZatcaError>` |
    | `report_simplified_invoice(invoice: &SignedInvoice, credentials: &CsidCredentials<Production>, clearance_status: bool, accept_language: Option<&str>)` | `Result<ValidationResponse, ZatcaError>` |
    | `clear_standard_invoice(invoice: &SignedInvoice, credentials: &CsidCredentials<Production>, clearance_status: bool, accept_language: Option<&str>)` | `Result<ValidationResponse, ZatcaError>` |

    **Credentials**

    `CsidCredentials::<Compliance>::new(env, request_id, token, secret)` creates compliance
    credentials; use `Production` for production scope. Arguments are `EnvironmentType`,
    `Option<String>`, and two `impl Into<String>` values. Construction returns the
    credential object directly.

    | Accessor | Returns |
    | --- | --- |
    | `credentials.env()` | `EnvironmentType` |
    | `credentials.request_id()` | `Option<&str>` |
    | `credentials.binary_security_token()` / `credentials.secret()` | `&str` |

    **Responses**

    | Method | Returns |
    | --- | --- |
    | `response.http_status()` | `Option<u16>` |
    | `response.outcome()` | `InvoiceOutcome::{Accepted, Rejected, Unknown}` |
    | `response.ensure_accepted()` | `Result<(), ZatcaError>` |
    | `response.validation_results()` | `&ValidationResults` |
    | `response.reporting_status()` / `clearance_status()` / `qr_seller_status()` / `qr_buyer_status()` | `Option<&str>` |
    | `response.cleared_invoice_base64()` | `Option<&str>` |
    | `response.cleared_invoice_xml()` | `Result<Option<String>, ZatcaError>` |
    | `results.status()` | `Option<&str>` |
    | `results.info_messages()` | `&MessageList`: `One`, `Many`, or `Empty` |
    | `results.warning_messages()` / `results.error_messages()` | `&[ValidationMessage]` |
    | `message.message_type()` / `code()` / `category()` / `message()` / `status()` | `Option<&str>` |

    These getters borrow the response. Serializing and deserializing the response body
    does not preserve HTTP status or operation context; the deserialized outcome is
    `Unknown`. `ZatcaError::NotAccepted` retains the response. For HTTP failures,
    `ZatcaError::http_status()` provides the status when available;
    `HttpResponseError::body()` and `validation_response()` expose the retained body
    and optional parsed response. See [error reference](errors.md).

    **Prepared requests**

    Prefix each HTTP method above with `prepare_` and use the same arguments. These
    synchronous methods return `Result<ComplianceRequest, ZatcaError>` for CSR issuance,
    `Result<ProductionRequest, ZatcaError>` for production issuance/renewal, and
    `Result<InvoiceRequest, ZatcaError>` for invoice operations.

    `prepared.request()` borrows an `HttpRequest`. Its `method()` and `url()` return
    `&str`, `headers()` returns `&[(String, String)]`, and `body()` returns `&[u8]`.
    `prepared.decode(status: u16, body: &[u8])` returns the corresponding response or
    credentials in `Result<_, ZatcaError>`. Preparing and decoding do not consume inputs.
    The request owns its data and can outlive the client, invoice, and credentials.

=== "Python"
    Import `ZatcaClient`, `CsidCompliance`, `CsidProduction`, and `InvoiceOutcome`
    from `fatoora`. Construct `ZatcaClient(config: Config)`. HTTP calls block until they
    finish and raise classified exceptions on failure; see [errors](errors.md).

    **HTTP operations**

    | Method on `client` | Returns |
    | --- | --- |
    | `post_csr_for_ccsid(csr: Csr, otp: str)` | `CsidCompliance` |
    | `post_ccsid_for_pcsid(ccsid: CsidCompliance)` | `CsidProduction` |
    | `renew_csid(pcsid: CsidProduction, csr: Csr, otp: str, accept_language: Optional[str] = None)` | `CsidProduction` |
    | `check_invoice_compliance(invoice: SignedInvoice, ccsid: CsidCompliance)` | `ValidationResponse` |
    | `report_simplified_invoice(invoice: SignedInvoice, pcsid: CsidProduction, clearance_status: bool, accept_language: Optional[str] = None)` | `ValidationResponse` |
    | `clear_standard_invoice(invoice: SignedInvoice, pcsid: CsidProduction, clearance_status: bool, accept_language: Optional[str] = None)` | `ValidationResponse` |

    **Credentials**

    `CsidCompliance.new(env: Environment, token: str, secret: str, request_id: Optional[str] = None)`
    returns `CsidCompliance`. `CsidProduction.new` accepts the same arguments and returns
    `CsidProduction`. `env()` returns `Environment`; `binary_security_token()` and
    `secret()` return `str`. `request_id()` returns `str`, using `""` when absent.

    **Responses**

    | Method | Returns |
    | --- | --- |
    | `response.http_status()` | `Optional[int]` |
    | `response.outcome()` | `InvoiceOutcome.ACCEPTED`, `.REJECTED`, or `.UNKNOWN` |
    | `response.ensure_accepted()` | `None`; raises `ApiError` if not accepted. |
    | `response.validation_results()` | `ValidationResults` |
    | `response.reporting_status()` / `clearance_status()` / `qr_seller_status()` / `qr_buyer_status()` | `Optional[str]` |
    | `response.cleared_invoice_base64()` | `Optional[str]` |
    | `response.cleared_invoice_xml()` | `Optional[str]`; raises `ParseError` for invalid content. |
    | `results.status()` | `Optional[str]` |
    | `results.info_messages()` / `warning_messages()` / `error_messages()` | `list[ValidationMessage]` |
    | `message.message_type()` / `code()` / `category()` / `message()` / `status()` | `Optional[str]` |

    Client, credential, response, result, and message objects support `with` and
    `close()`. Child results are independently owned. Calls do not consume their
    inputs. The public Python facade provides the blocking HTTP methods above;
    prepared-request methods are not exposed by this facade.

=== "JavaScript"
    Import `ZatcaClient`, `CsidCompliance`, `CsidProduction`, and `InvoiceOutcome`
    from `fatoority`. Create `new ZatcaClient(config, { fetch })`; the second argument
    is optional and defaults to `globalThis.fetch`. Calls return promises; use `await`.

    **HTTP operations**

    | Method on `client` | Promise resolves to |
    | --- | --- |
    | `postCsrForCcsid(csr, otp, options = {})` | `CsidCompliance` |
    | `postCcsidForPcsid(credentials, options = {})` | `CsidProduction` |
    | `renewCsid(credentials, csr, otp, acceptLanguage = null, options = {})` | `CsidProduction` |
    | `checkInvoiceCompliance(invoice, credentials, options = {})` | `ValidationResponse` |
    | `reportSimplifiedInvoice(invoice, credentials, clearanceStatus = false, acceptLanguage = null, options = {})` | `ValidationResponse` |
    | `clearStandardInvoice(invoice, credentials, clearanceStatus = true, acceptLanguage = null, options = {})` | `ValidationResponse` |

    Pass `Csr` for `csr`, `SignedInvoice` for `invoice`, strings for OTP/language, and
    boolean clearance flags. Compliance issuance uses no credential; compliance checks
    and production issuance take `CsidCompliance`; reporting, clearance, and renewal
    take `CsidProduction`. Each `options` accepts `{ signal: AbortSignal }` for cancellation.
    Transport failures reject with `TransportError`; response/acceptance failures reject with an `Error` whose cause is
    `BindingError`. See [JavaScript HTTP setup](bindings/javascript.md#api-requests)
    for browser CORS and custom fetch behavior.

    **Credentials**

    `CsidCompliance.create(environment, requestId, token, secret)` returns compliance
    credentials; `CsidProduction.create` returns production credentials. Pass environment
    number `0`, `1`, or `2`, a string or `null` request ID, and string token/secret.
    `env()` returns the number; `binarySecurityToken()` and `secret()` return strings;
    `requestId()` returns `Text` or `null`. Read optional text with `text?.value()`.

    **Responses**

    | Method | Returns |
    | --- | --- |
    | `response.httpStatus()` | Number or `null` |
    | `response.outcome()` | `InvoiceOutcome.Accepted`, `.Rejected`, or `.Unknown` |
    | `response.ensureAccepted()` | `undefined`; throws unless accepted. |
    | `response.validationResults()` | `ValidationResults` |
    | `response.reportingStatus()` / `clearanceStatus()` / `qrSellerStatus()` / `qrBuyerStatus()` | `Text` or `null` |
    | `response.clearedInvoiceBase64()` / `clearedInvoiceXml()` | `Text` or `null`; XML decoding can throw. |
    | `results.status()` | `Text` or `null` |
    | `results.infoLen()` / `warningLen()` / `errorLen()` | Number of messages |
    | `results.infoMessage(index)` / `warningMessage(index)` / `errorMessage(index)` | `ValidationMessage` |
    | `message.messageType()` / `code()` / `category()` / `message()` / `status()` | `Text` or `null` |

    Message indexes are zero-based and must be less than the corresponding length.
    Child handles are independently owned. Calls do not consume inputs. See
    [JavaScript resource handling](bindings/javascript.md) for binary data lifetimes.

    **Prepared requests**

    For custom transport, import `ZatcaClient as RequestClient` from `fatoority/raw` and
    create it with `RequestClient.create(config)`. Its synchronous methods are
    `preparePostCsrForCcsid`, `preparePostCcsidForPcsid`, `prepareRenewCsid`,
    `prepareCheckInvoiceCompliance`, `prepareReportSimplifiedInvoice`, and
    `prepareClearStandardInvoice`. They take the same operation arguments as above,
    without `options`; supply the clearance boolean and nullable language explicitly.
    They return `ComplianceRequest`, `ProductionRequest`, or `InvoiceRequest` according
    to the operation.

    `request.method()`, `url()`, and `headersJson()` return strings; `body()` returns
    `Bytes`. `request.decode(status, body)` takes an HTTP status number and an array of
    byte numbers and returns the corresponding credentials or validation response.
    Alternatively, `await sendPrepared(request, { fetch, signal })` from `fatoority`
    sends and decodes the request. Preparation owns its data; it does not send HTTP.

=== "C#"
    Use the `Fatoora` namespace. `ZatcaClient.Create(config: Config)` returns a client.
    HTTP methods block; errors throw `BindingErrorException`. Use `using` for owned
    objects, including child responses and optional `Text` values.

    **HTTP operations**

    | Method on `client` | Inputs in order | Returns |
    | --- | --- | --- |
    | `PostCsrForCcsid` | `Csr csr`, `string otp` | `CsidCompliance` |
    | `PostCcsidForPcsid` | `CsidCompliance credentials` | `CsidProduction` |
    | `RenewCsid` | `CsidProduction credentials`, `Csr csr`, `string otp`, `string? acceptLanguage` | `CsidProduction` |
    | `CheckInvoiceCompliance` | `SignedInvoice invoice`, `CsidCompliance credentials` | `ValidationResponse` |
    | `ReportSimplifiedInvoice` | `SignedInvoice invoice`, `CsidProduction credentials`, `bool clearanceStatus`, `string? acceptLanguage` | `ValidationResponse` |
    | `ClearStandardInvoice` | `SignedInvoice invoice`, `CsidProduction credentials`, `bool clearanceStatus`, `string? acceptLanguage` | `ValidationResponse` |

    Pass `null` explicitly when omitting response language.

    **Credentials**

    `CsidCompliance.Create(environment, requestId, token, secret)` returns
    compliance credentials; `CsidProduction.Create` returns production credentials.
    Pass `byte` environment `0`, `1`, or `2`, a nullable `string` request ID,
    and `string` token/secret. `Env()` returns `byte`;
    `BinarySecurityToken()` and `Secret()` return `string`;
    `RequestId()` returns nullable `Text`.
    Read text with `Value()` and dispose the `Text` object when finished.

    **Responses**

    | Method | Returns |
    | --- | --- |
    | `response.HttpStatus()` | `ushort?` |
    | `response.Outcome()` | `InvoiceOutcome` (`Accepted`, `Rejected`, `Unknown`) |
    | `response.EnsureAccepted()` | No value; throws unless accepted. |
    | `response.ValidationResults()` | `ValidationResults` |
    | `response.ReportingStatus()` / `ClearanceStatus()` / `QrSellerStatus()` / `QrBuyerStatus()` | Nullable `Text` |
    | `response.ClearedInvoiceBase64()` / `ClearedInvoiceXml()` | Nullable `Text`; XML decoding can throw. |
    | `results.Status()` | Nullable `Text` |
    | `results.InfoLen()` / `WarningLen()` / `ErrorLen()` | `nuint` message count |
    | `results.InfoMessage(index)` / `WarningMessage(index)` / `ErrorMessage(index)` | `ValidationMessage` |
    | `message.MessageType()` / `Code()` / `Category()` / `Message()` / `Status()` | Nullable `Text` |

    Use zero-based `nuint` indexes below the corresponding message count. Child
    objects are independently owned. Methods do not consume their inputs.

    **Prepared requests**

    Use the six methods `PreparePostCsrForCcsid`,
    `PreparePostCcsidForPcsid`, `PrepareRenewCsid`,
    `PrepareCheckInvoiceCompliance`, `PrepareReportSimplifiedInvoice`,
    and `PrepareClearStandardInvoice` with the same inputs as their HTTP
    counterparts. They return `ComplianceRequest` for compliance credentials,
    `ProductionRequest` for production credentials/renewal, and `InvoiceRequest` for
    invoice operations, without sending HTTP.

    `request.Method()`, `Url()`, and `HeadersJson()`
    return `string`; `Body()` returns owned `Bytes`.
    `request.Decode(status, body)` accepts `ushort` HTTP status and
    `byte[]` response body, and returns the matching credential or response type.
    Prepared requests own their input data and may outlive the original client and inputs.

=== "Kotlin"
    Import types from `com.fatoora`. `ZatcaClient.create(config)` takes `Config` and
    returns a client. HTTP methods block and errors raise exceptions. Use `.use { ... }` or `close()` for owned objects,
    including child responses and optional `Text` values.

    **HTTP operations**

    | Method on `client` | Inputs in order | Returns |
    | --- | --- | --- |
    | `postCsrForCcsid` | `Csr csr`, `String otp` | `CsidCompliance` |
    | `postCcsidForPcsid` | `CsidCompliance credentials` | `CsidProduction` |
    | `renewCsid` | `CsidProduction credentials`, `Csr csr`, `String otp`, `String? acceptLanguage` | `CsidProduction` |
    | `checkInvoiceCompliance` | `SignedInvoice invoice`, `CsidCompliance credentials` | `ValidationResponse` |
    | `reportSimplifiedInvoice` | `SignedInvoice invoice`, `CsidProduction credentials`, `Boolean clearanceStatus`, `String? acceptLanguage` | `ValidationResponse` |
    | `clearStandardInvoice` | `SignedInvoice invoice`, `CsidProduction credentials`, `Boolean clearanceStatus`, `String? acceptLanguage` | `ValidationResponse` |

    Response language defaults to `null`; an overload allows it to be omitted.

    **Credentials**

    `CsidCompliance.create(environment, requestId, token, secret)` returns
    compliance credentials; `CsidProduction.create` returns production credentials.
    Pass `Int` environment `0`, `1`, or `2`, a nullable `String` request ID,
    and `String` token/secret. `env()` returns `Int`;
    `binarySecurityToken()` and `secret()` return `String`;
    `requestId()` returns nullable `Text`.
    Read text with `value()` and dispose the `Text` object when finished.

    **Responses**

    | Method | Returns |
    | --- | --- |
    | `response.httpStatus()` | `Int?` |
    | `response.outcome()` | `InvoiceOutcome` (`Accepted`, `Rejected`, `Unknown`) |
    | `response.ensureAccepted()` | No value; throws unless accepted. |
    | `response.validationResults()` | `ValidationResults` |
    | `response.reportingStatus()` / `clearanceStatus()` / `qrSellerStatus()` / `qrBuyerStatus()` | Nullable `Text` |
    | `response.clearedInvoiceBase64()` / `clearedInvoiceXml()` | Nullable `Text`; XML decoding can throw. |
    | `results.status()` | Nullable `Text` |
    | `results.infoLen()` / `warningLen()` / `errorLen()` | `java.math.BigInteger` message count |
    | `results.infoMessage(index)` / `warningMessage(index)` / `errorMessage(index)` | `ValidationMessage` |
    | `message.messageType()` / `code()` / `category()` / `message()` / `status()` | Nullable `Text` |

    Use zero-based `java.math.BigInteger` indexes below the corresponding message count. Child
    objects are independently owned. Methods do not consume their inputs.

    **Prepared requests**

    Use the six methods `preparePostCsrForCcsid`,
    `preparePostCcsidForPcsid`, `prepareRenewCsid`,
    `prepareCheckInvoiceCompliance`, `prepareReportSimplifiedInvoice`,
    and `prepareClearStandardInvoice` with the same inputs as their HTTP
    counterparts. They return `ComplianceRequest` for compliance credentials,
    `ProductionRequest` for production credentials/renewal, and `InvoiceRequest` for
    invoice operations, without sending HTTP.

    `request.method()`, `url()`, and `headersJson()`
    return `String`; `body()` returns owned `Bytes`.
    `request.decode(status, body)` accepts `Int` HTTP status and
    `ByteArray` response body, and returns the matching credential or response type.
    Prepared requests own their input data and may outlive the original client and inputs.

=== "Java"
    Import types from `com.fatoora`. `ZatcaClient.create(config)` takes `Config` and
    returns a client. HTTP methods block and errors raise exceptions. Use try-with-resources or `close()` for owned objects,
    including child responses and optional `Text` values.

    **HTTP operations**

    | Method on `client` | Inputs in order | Returns |
    | --- | --- | --- |
    | `postCsrForCcsid` | `Csr csr`, `String otp` | `CsidCompliance` |
    | `postCcsidForPcsid` | `CsidCompliance credentials` | `CsidProduction` |
    | `renewCsid` | `CsidProduction credentials`, `Csr csr`, `String otp`, `String (nullable) acceptLanguage` | `CsidProduction` |
    | `checkInvoiceCompliance` | `SignedInvoice invoice`, `CsidCompliance credentials` | `ValidationResponse` |
    | `reportSimplifiedInvoice` | `SignedInvoice invoice`, `CsidProduction credentials`, `boolean clearanceStatus`, `String (nullable) acceptLanguage` | `ValidationResponse` |
    | `clearStandardInvoice` | `SignedInvoice invoice`, `CsidProduction credentials`, `boolean clearanceStatus`, `String (nullable) acceptLanguage` | `ValidationResponse` |

    Response language defaults to `null`; an overload allows it to be omitted.

    **Credentials**

    `CsidCompliance.create(environment, requestId, token, secret)` returns
    compliance credentials; `CsidProduction.create` returns production credentials.
    Pass `int` environment `0`, `1`, or `2`, a nullable `String` request ID,
    and `String` token/secret. `env()` returns `int`;
    `binarySecurityToken()` and `secret()` return `String`;
    `requestId()` returns nullable `Text`.
    Read text with `value()` and dispose the `Text` object when finished.

    **Responses**

    | Method | Returns |
    | --- | --- |
    | `response.httpStatus()` | `Integer (nullable)` |
    | `response.outcome()` | `InvoiceOutcome` (`Accepted`, `Rejected`, `Unknown`) |
    | `response.ensureAccepted()` | No value; throws unless accepted. |
    | `response.validationResults()` | `ValidationResults` |
    | `response.reportingStatus()` / `clearanceStatus()` / `qrSellerStatus()` / `qrBuyerStatus()` | Nullable `Text` |
    | `response.clearedInvoiceBase64()` / `clearedInvoiceXml()` | Nullable `Text`; XML decoding can throw. |
    | `results.status()` | Nullable `Text` |
    | `results.infoLen()` / `warningLen()` / `errorLen()` | `java.math.BigInteger` message count |
    | `results.infoMessage(index)` / `warningMessage(index)` / `errorMessage(index)` | `ValidationMessage` |
    | `message.messageType()` / `code()` / `category()` / `message()` / `status()` | Nullable `Text` |

    Use zero-based `java.math.BigInteger` indexes below the corresponding message count. Child
    objects are independently owned. Methods do not consume their inputs.

    **Prepared requests**

    Use the six methods `preparePostCsrForCcsid`,
    `preparePostCcsidForPcsid`, `prepareRenewCsid`,
    `prepareCheckInvoiceCompliance`, `prepareReportSimplifiedInvoice`,
    and `prepareClearStandardInvoice` with the same inputs as their HTTP
    counterparts. They return `ComplianceRequest` for compliance credentials,
    `ProductionRequest` for production credentials/renewal, and `InvoiceRequest` for
    invoice operations, without sending HTTP.

    `request.method()`, `url()`, and `headersJson()`
    return `String`; `body()` returns owned `Bytes`.
    `request.decode(status, body)` accepts `int` HTTP status and
    `byte[]` response body, and returns the matching credential or response type.
    Prepared requests own their input data and may outlive the original client and inputs.

=== "C"
    Include `fatoora.h`. Every operation returns `FatooraStatus`; `FATOORA_OK` means
    its output was written. Other statuses indicate failure; inspect the optional
    `FatooraError`. Calls borrow inputs and block while sending HTTP.

    **Client and credentials**

    ```c
    FatooraStatus fatoora_zatca_client_create(const FatooraConfig *config,
        FatooraZatcaClient **out,
        FatooraError **error);
    FatooraStatus fatoora_zatca_client_post_csr_for_ccsid(const FatooraZatcaClient *self,
        const FatooraCsr *csr,
        const char *otp,
        FatooraCsidCompliance **out,
        FatooraError **error);
    FatooraStatus fatoora_zatca_client_post_ccsid_for_pcsid(const FatooraZatcaClient *self,
        const FatooraCsidCompliance *credentials,
        FatooraCsidProduction **out,
        FatooraError **error);
    FatooraStatus fatoora_zatca_client_renew_csid(const FatooraZatcaClient *self,
        const FatooraCsidProduction *credentials,
        const FatooraCsr *csr,
        const char *otp,
        const char *accept_language,
        FatooraCsidProduction **out,
        FatooraError **error);
    FatooraStatus fatoora_zatca_client_check_invoice_compliance(const FatooraZatcaClient *self,
        const FatooraSignedInvoice *invoice,
        const FatooraCsidCompliance *credentials,
        FatooraValidationResponse **out,
        FatooraError **error);
    FatooraStatus fatoora_zatca_client_report_simplified_invoice(const FatooraZatcaClient *self,
        const FatooraSignedInvoice *invoice,
        const FatooraCsidProduction *credentials,
        bool clearance_status,
        const char *accept_language,
        FatooraValidationResponse **out,
        FatooraError **error);
    FatooraStatus fatoora_zatca_client_clear_standard_invoice(const FatooraZatcaClient *self,
        const FatooraSignedInvoice *invoice,
        const FatooraCsidProduction *credentials,
        bool clearance_status,
        const char *accept_language,
        FatooraValidationResponse **out,
        FatooraError **error);
    FatooraStatus fatoora_csid_compliance_create(int32_t environment,
        const char *request_id,
        const char *token,
        const char *secret,
        FatooraCsidCompliance **out,
        FatooraError **error);
    FatooraStatus fatoora_csid_production_create(int32_t environment,
        const char *request_id,
        const char *token,
        const char *secret,
        FatooraCsidProduction **out,
        FatooraError **error);
    ```

    Environment values are `0` non-production, `1` simulation, and `2` production.
    Use `NULL` for absent request ID or language. Text inputs are UTF-8 strings.
    Credential getters start with `fatoora_csid_compliance_` or
    `fatoora_csid_production_`, take `const` credential pointer, output pointer, and
    `FatooraError **error`. `env` writes `uint8_t`; `request_id`, `binary_security_token`,
    and `secret` write owned `char *`, with `NULL` for absent request ID.

    **Responses**

    Each getter takes `const FatooraValidationResponse *self`, the output argument
    below, then `FatooraError **error`. `ensure_accepted` takes only `self` and `error`.

    | Function | Output |
    | --- | --- |
    | `fatoora_validation_response_http_status` | `uint16_t *out`, `bool *has_value` |
    | `fatoora_validation_response_outcome` | `FatooraInvoiceOutcome *out` |
    | `fatoora_validation_response_ensure_accepted` | No output; `FATOORA_OK` only if accepted. |
    | `fatoora_validation_response_validation_results` | `FatooraValidationResults **out` |
    | `fatoora_validation_response_reporting_status` | `char **out` |
    | `fatoora_validation_response_clearance_status` | `char **out` |
    | `fatoora_validation_response_qr_seller_status` | `char **out` |
    | `fatoora_validation_response_qr_buyer_status` | `char **out` |
    | `fatoora_validation_response_cleared_invoice_base64` | `char **out` |
    | `fatoora_validation_response_cleared_invoice_xml` | `char **out`; decoding can fail. |

    Optional text returns `NULL` for absence, distinct from a present empty string.
    Result getters use the `fatoora_validation_results_` prefix:
    `status(self, char **out, error)` returns optional text;
    `info_len`, `warning_len`, and `error_len` use `size_t *out`;
    `info_message`, `warning_message`, and `error_message` take `self`, zero-based
    `size_t index`, `FatooraValidationMessage **out`, and `error`. Indexes must be below
    the corresponding length.

    Message getters use `fatoora_validation_message_` with suffixes `message_type`,
    `code`, `category`, `message`, and `status`. Each takes `self`, `char **out`, and
    `error`, returning optional owned text.

    **Prepared requests**

    Add `prepare_` after `fatoora_zatca_client_` in the six HTTP function names above.
    Inputs are identical; the output changes to `FatooraComplianceRequest **` for CSR
    issuance, `FatooraProductionRequest **` for production issuance/renewal, or
    `FatooraInvoiceRequest **` for invoice operations.

    Request accessors use `fatoora_compliance_request_`, `fatoora_production_request_`,
    or `fatoora_invoice_request_`. `method`, `url`, and `headers_json` take `self`,
    `char **out`, and `error`; `body` uses `FatooraBytes **out`.
    `decode` takes `self`, `uint16_t status`, `const uint8_t *body`, `size_t body_len`,
    the matching credential/response output pointer, and `error`.
    The request owns its data and does not send HTTP until your transport does so.

    **Ownership**

    Outputs and response children are independent owned copies. Release text with
    `fatoora_string_free`; release handles with their matching `_free` function, such
    as `fatoora_zatca_client_free`, `fatoora_csid_compliance_free`,
    `fatoora_csid_production_free`, `fatoora_validation_response_free`,
    `fatoora_validation_results_free`, `fatoora_validation_message_free`, or
    `fatoora_invoice_request_free`. See [C ownership and errors](bindings/c.md).

## Related reference

- [Environment configuration](configuration.md)
- [CSR and private keys](csr.md)
- [Invoice signing](invoice-signing.md)
- [Error handling](errors.md)
