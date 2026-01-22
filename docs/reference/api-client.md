# ZATCA API Client

## Types
- `ZatcaError` covers HTTP/client errors, invalid responses, unauthorized/server responses, and
  client state issues.
- `TokenScope` is a marker trait for token types; use `Compliance` (CCSID) or `Production` (PCSID).
- `ZatcaClient` is the HTTP client wrapper configured with `Config` and environment URLs.
- `ValidationResponse` and `ValidationResults` wrap ZATCA validation responses (info/warning/error
  messages and status fields).
- `ValidationMessage` and `MessageList` model per-message details returned by the API.
- `UnauthorizedResponse` and `ServerErrorResponse` model error response bodies.
- `CsidCredentials<T>` stores CSID credentials (request ID, binary security token, secret) and the
  environment associated with the credentials.

## Endpoints
- Compliance APIs: request CSIDs from CSR (`post_csr_for_ccsid`), exchange CCSID for PCSID
  (`post_ccsid_for_pcsid`), and renew credentials (`post_renew_for_ccsid`).
- Invoice APIs: reporting and clearance endpoints for simplified and standard invoices
  (`post_reporting`, `post_clearance`) and compliance checks (`post_compliance`).
- FFI bindings expose responses via opaque handles with getter functions (no JSON payloads).

See also: [API Client Guide](../guides/api.md)
