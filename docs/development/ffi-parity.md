# FFI capability and contract coverage

The [Rust core](../../fatoora-core/src) defines behavior. The Diplomat bridge in
[fatoora-ffi](../../fatoora-ffi/src) exposes that behavior through generated C,
C++, and Nanobind bindings. The public [Python facade](../../bindings/python/fatoora/api.py)
handles Python values, exceptions, and lifetimes. CFFI and the former handwritten
C ABI have been removed.

This table maps exposed capabilities to bridge methods and regression coverage.
Exposure does not imply that every platform build has passed. See
[Diplomat bindings](diplomat.md) for generation, ownership, and verification status.
Generated C names follow `fatoora_Type_method`; C++ uses `fatoora::Type::method`.

| Capability | Bridge type and methods | Contract coverage |
| --- | --- | --- |
| Environment and configuration | `Config::{new,env}` | Rust crypto tests; C/C++ contracts reject unknown environments |
| Signing keys | `SigningKey::{generate,from_pem,from_der,to_pem,to_der}` | Rust crypto tests; C++ key DER roundtrip; Python documentation examples |
| CSR configuration | `CsrProperties::{new,from_properties_str,parse_csr_config_file,build}` | Rust crypto tests; C++ construction and environment rejection; Python examples |
| CSR serialization and extensions | `Csr::{from_der,to_der,to_pem,to_base64,to_pem_base64,subject_string,extension_values_der}` | C++ DER roundtrip and detached extension bytes; Rust byte-list bounds checks |
| Invoice construction | `InvoiceBuilder::new`, setters, `add_line_item`, `build` | C/C++ exact-decimal and consumption contracts; Python builder and numeric tests |
| Finalized invoice parsing and XML | `FinalizedInvoice::{from_xml,from_file,data,totals,hash_base64,xml}` | C/C++ XML rounding; Python parsing, numeric, and documentation tests |
| Signed invoice parsing and XML ownership | `SignedInvoice::{from_xml,from_file,xml,into_xml,to_xml_base64}` | C++ exact fixture bytes and consumed-state errors; Python ownership tests |
| Invoice snapshots | `InvoiceData`, `Party`, `Address`, `VatId`, `OtherId`, `InvoiceNote`, `OriginalInvoiceRef`, `InvoiceLineItem`, `InvoiceTotals` accessors | C++ detached data/party/address/line owners; Python numeric/address tests |
| Signing and certificates | `Signer::{from_pem,from_der,certificate_pem,certificate_der,sign}` | Rust invalid certificate/key tests; Python signing examples |
| Raw XML signing | `Signer::sign_xml` | Exposed through generated bindings and Python facade; signing regressions belong with the signing tests |
| Raw XML hashing | `Xml::hash`; Python `invoice_hash_base64_from_xml_str` | Exposed through generated bindings and Python facade; hash equivalence regressions belong with XML tests |
| XML validation | `Xml::validate`; Python `validate_xml_invoice_from_str` | Python validation/error tests; core XML validation regressions |
| Signature and QR metadata | `SignedInvoice::{qr_code,signature,public_key,invoice_hash,issuer,serial,cert_hash,signed_props_hash,signing_time,zatca_key_signature}` | Python signing and documentation examples; signed XML fixture contracts |
| CSID credentials | `CsidCompliance` and `CsidProduction`: `create`, `env`, `request_id`, `binary_security_token`, `secret` | Python HTTP/credential tests; optional text preserves absence |
| Onboarding and renewal | `ZatcaClient::{create,post_csr_for_ccsid,post_ccsid_for_pcsid,renew_csid}` | Python API examples and Rust API tests; generated blocking Python aliases release the GIL |
| Compliance, reporting, clearance | `ZatcaClient::{check_invoice_compliance,report_simplified_invoice,clear_standard_invoice}` | Python local-gateway tests preserve HTTP status, body, endpoint, and error classification |
| Response acceptance and cleared XML | `ValidationResponse::{http_status,outcome,ensure_accepted,cleared_invoice_xml,cleared_invoice_base64}` and status accessors | Python accepted/rejected/unknown outcomes and missing/invalid cleared-invoice tests |
| Validation messages | `ValidationResponse::validation_results`, `ValidationResults` indexed message accessors, `ValidationMessage` accessors | Python response tests; owned snapshots and bounds errors |
| Structured errors | `BindingError::{code,message,details_json}` | C/C++ error lifetime tests; Python known/unknown codes and validation details; Rust panic containment |
| Owned optional text and bytes | `Text::value`, `Bytes::as_slice`, `BytesList::{len,is_empty,get}` | C++ independent byte owners; Python conversion to owned strings and bytes |

## Changing a capability

1. Define the core behavior and its regression case.
2. Extend the relevant [bridge module](../../fatoora-ffi/src).
3. Run [generate_bindings.py](../../scripts/generate_bindings.py), then its `--check` mode.
4. Update the Python facade where the public operation needs conversions or locking.
5. Exercise the generated ABI and installed Python wheel. Include failure paths,
   owned-output lifetimes, and consumption where they apply.

Raw XML signing and hashing are now exposed; they are no longer missing binding
capabilities. Country, currency, and timestamp values cross the boundary as
validated strings. Internal views and serialization helpers remain implementation
details; this interface does not promise a separate foreign type for every Rust
type. Structured errors cross as numeric classification, message, and JSON details.

## Regression entry points

- [test_crypto_bytes.py](../../bindings/python/tests/test_crypto_bytes.py): key and
  CSR DER roundtrips, owned extension bytes, and certificate fixture equality.
- [test_public_api.py](../../bindings/python/tests/test_public_api.py): preserved
  public methods and argument names, with obsolete loader/dependency removal.

- [diplomat_contract.c](../../fatoora-ffi/tests/diplomat_contract.c) and
  [diplomat_contract.cpp](../../fatoora-ffi/tests/diplomat_contract.cpp): generated
  ABI, invalid UTF-8/NUL, unknown enum values, decimal recovery, rounding,
  consumption, independent owners, signed XML, and DER roundtrips.
- [test_numeric_contract.py](../../bindings/python/tests/test_numeric_contract.py):
  decimal fidelity, half-up rounding, imported totals, and address fields.
- [test_builder_ownership.py](../../bindings/python/tests/test_builder_ownership.py)
  and [test_ownership.py](../../bindings/python/tests/test_ownership.py): recoverable
  setters, consumed builders, copied and consumed signed XML.
- [test_errors.py](../../bindings/python/tests/test_errors.py): error classification,
  unknown codes, structured validation issues, and malformed input.
- [test_api_responses.py](../../bindings/python/tests/test_api_responses.py): local
  HTTP responses, acceptance semantics, and cleared-invoice decoding.
- [test_doc_examples.py](../../bindings/python/tests/test_doc_examples.py): executable
  public workflows.
- [wheel_smoke.py](../../bindings/python/tests/wheel_smoke.py): installed package
  loading and representative operations.

Tests tied to handwritten CFFI declarations or opaque-handle layouts are replaced
by generated C/C++ contracts. Public behavior tests remain acceptance criteria for
the Python facade. HTTP tests must use a Python server thread to detect calls that
incorrectly retain the GIL. Concurrency regressions must also check that close or
consumption waits while another operation uses the same owner.
