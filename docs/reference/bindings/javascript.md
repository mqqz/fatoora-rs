---
title: JavaScript and TypeScript ZATCA E-Invoicing Library
description: JavaScript package reference for fatoority. Learn supported runtimes, exact decimal values, validation results, errors, and asynchronous ZATCA API requests.
---

# JavaScript package reference

Use `fatoority` in Node.js or a browser to build, sign, and validate invoices and
send ZATCA API requests. The package includes WebAssembly and TypeScript declarations.
For a complete task walkthrough, start with the [guides](../../guides/validation.md).

## Install

```sh
npm install fatoority
```

Import from the package root for asynchronous API requests and validation with an
automatically supplied clock:

```js
import { Config, SigningKey, Xml, ZatcaClient } from 'fatoority';

const config = Config.new_(0);
const key = SigningKey.generate();
const privateKeyPem = key.toPem();
```

The private key is secret material; store it securely. Environment values are `0` (nonproduction), `1` (simulation), and
`2` (production). Configuration, CSR generation, and credentials must agree.

Node.js 22+ and modern browsers are supported. Browser execution requires
WebAssembly, Web Crypto, `FinalizationRegistry`, and top-level await. TypeScript
users can use `NodeNext` or `bundler` module resolution; no separate `@types`
package is needed.

## Values, ownership and errors

| Value | JavaScript representation and behavior |
| --- | --- |
| Text | `string`; embedded NUL is rejected |
| Optional text input | `string` or `null`; `""` is a present empty value |
| Optional text output | `Text` object or `null`; call `value()` when present |
| Decimal amount or quantity | Exact decimal `string`, such as `"15.25"`; do not pass a floating-point number |
| Invoice counter | `bigint`, within the unsigned 64-bit range |
| Binary output | `Bytes.asSlice()` returns a copied `number[]`; use `Uint8Array.from(...)` for a typed byte array |
| Native object | Object managed by `FinalizationRegistry` |
| Invoice outcome | `InvoiceOutcome.Accepted`, `Rejected`, or `Unknown` |

Method names use camelCase. Constructors named `new` in the underlying API use
`new_`, such as `Config.new_(0)`. Read the [number reference](../numbers.md) for
accepted decimal syntax and rounding rules.

`InvoiceBuilder.build()`, `Signer.sign()`, and `SignedInvoice.intoXml()` consume
the object's inner state. Build and signing failures can also consume state;
create a new input object before retrying. Subsequent use of consumed state
throws an error. Returned invoice data, addresses, totals, and response children
are independent snapshots.

Objects belong to the WebAssembly instance that created them. Each worker needs
its own instance and objects; do not transfer internal pointers between workers.
Garbage collection does not guarantee immediate cleanup or erasure of secrets.

A library failure throws an `Error` with a `BindingError` in `cause`. Read
`code()`, `message()`, and `detailsJson()` from that cause. The JSON contains
structured information such as validation findings or an HTTP response body.
See [error codes and details](../errors.md).

```js
try {
  Config.new_(99);
} catch (error) {
  const details = JSON.parse(error.cause.detailsJson());
  console.error(error.cause.code(), error.cause.message(), details);
}
```

Network, cancellation, and response-body read failures throw `TransportError`.
It preserves the original `cause`; `httpStatus` is present when a response was
received but its body could not be read. HTTP rejection decoded by the library
uses the structured library error instead.

## Local validation

| Method | Inputs | Returns |
| --- | --- | --- |
| `Xml.validate(config, xml)` | Live `Config`, invoice XML string | `true` on schema success; throws on invalid XML or schema rejection |
| `Xml.validateZatca(config, xml, optionsJson?)` | Live `Config`, invoice XML, optional JSON string or `null` | JSON report string, including rejection or incomplete coverage |
| `Xml.hash(xml)` | Invoice XML string | Base64 invoice hash; throws when XML cannot be processed |

For Node.js, save your invoice as `invoice.xml` and read it as UTF-8:

```js
import { readFile } from 'node:fs/promises';
import { Config, Xml } from 'fatoority';

const invoiceXml = await readFile('invoice.xml', 'utf8');
const config = Config.new_(0);
const report = JSON.parse(Xml.validateZatca(config, invoiceXml));
console.log(report.is_valid, report.is_complete);
```

`optionsJson` accepts `previous_invoice_hash` and `evaluated_at`. Use
`JSON.stringify({ previous_invoice_hash: previousHash })` to supply invoice-history
context. `evaluated_at` is an RFC3339 timestamp; the package root supplies the
current time once if omitted. Set it explicitly for repeatable checks. The
`fatoority/raw` validation API requires an explicit timestamp.

A returned report does not imply validity: inspect `is_valid`. Missing predecessor
context produces incomplete coverage. Execution failures throw and may include a
partial report in the error details. See the [validation reference](../invoice-validation.md)
for fields, stage statuses, and limits. Local validation does not establish
remote acceptance or certificate issuer trust. Read files using Node.js or browser
APIs and pass their contents; filesystem helpers are not available in WebAssembly.

## API requests

Create `new ZatcaClient(config)` to use the global `fetch`, or
`new ZatcaClient(config, { fetch: customFetch })` to provide a compatible transport.
All methods below return promises. Optional `options` accepts `{ signal }`, where
`signal` is an `AbortSignal`.

| Method | Inputs | Promise result |
| --- | --- | --- |
| `postCsrForCcsid(csr, otp, options?)` | `Csr`, OTP string | `CsidCompliance` |
| `postCcsidForPcsid(credentials, options?)` | `CsidCompliance` | `CsidProduction` |
| `renewCsid(credentials, csr, otp, acceptLanguage?, options?)` | `CsidProduction`, `Csr`, OTP, optional language string | `CsidProduction` |
| `checkInvoiceCompliance(invoice, credentials, options?)` | `SignedInvoice`, `CsidCompliance` | `ValidationResponse` |
| `reportSimplifiedInvoice(invoice, credentials, clearanceStatus?, acceptLanguage?, options?)` | `SignedInvoice`, `CsidProduction`; status defaults to `false`, language to `null` | `ValidationResponse` |
| `clearStandardInvoice(invoice, credentials, clearanceStatus?, acceptLanguage?, options?)` | `SignedInvoice`, `CsidProduction`; status defaults to `true`, language to `null` | `ValidationResponse` |

`clearanceStatus` controls the clearance-status request header; it is not the
result of the operation. `acceptLanguage` controls the language request header.
Pass optional positional arguments explicitly when supplying a later argument.

HTTP success alone does not establish invoice acceptance. Inspect `outcome()` or
call `ensureAccepted()` on a `ValidationResponse`. For clearance,
`clearedInvoiceXml()` returns a nullable `Text` owner; call `value()` and save the
returned document when present. See [API requests and responses](../api-client.md) for
credential requirements and response fields, and the [API guide](../../guides/api.md)
for a complete workflow.

### Prepared requests

For your own HTTP integration, import `ZatcaClient` from `fatoority/raw`, construct
it with `ZatcaClient.create(config)`, and call its `prepare*` methods. These return
`ComplianceRequest`, `ProductionRequest`, or `InvoiceRequest` objects.

| Request method | Return value |
| --- | --- |
| `method()` | HTTP method string |
| `url()` | Complete request URL string |
| `headersJson()` | JSON array of header-name/value pairs |
| `body()` | `Bytes`; use `asSlice()` for a copied request body |
| `decode(status, bytes)` | Credentials or `ValidationResponse`, depending on request type; may throw |

Prepared requests retain their data and decoding context independently of the
original invoice and credentials. Copy the outgoing body before awaiting HTTP.
Pass every HTTP status and its response bytes to `decode`, including non-2xx
responses. Disable redirects. Headers contain credentials and should not be logged.

Alternatively, `sendPrepared(request, { fetch, signal })` from `fatoority` performs
these steps and returns a promise for the decoded result. It copies the body
before awaiting, refuses redirects, and forwards HTTP error responses to decoding.

## Browser deployment

The loader resolves `fatoora_ffi.wasm` relative to its package modules. Deploy the
modules and WASM together, or configure your bundler to copy WASM to that URL.
Serve the application over HTTP(S), with WebAssembly execution and Web Crypto
available.

Direct ZATCA requests depend on gateway CORS. Use a server-side transport when
needed and decide where credentials and private keys should reside. Local
validation runs without Java, external SDK files, or network access.

## Licensing and source builds

The package contains ZATCA-derived rules and messages with additional terms in
[third-party notices](https://github.com/mqqz/fatoority/blob/main/THIRD_PARTY_NOTICES.md).
TypeScript declarations ship with the package. For source-build instructions,
see the [binding development documentation](../../development/diplomat.md).
