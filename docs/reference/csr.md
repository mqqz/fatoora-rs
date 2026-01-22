# CSR

## Types
- `CsrProperties` holds the required CSR fields parsed from a properties string (common name,
  serial number, org identifiers, country, invoice type, location, business category). It
  validates non-empty fields and country code format.
- `CsrError` covers file I/O, properties parsing, missing keys, invalid subject/SAN construction,
  CSR build failures, and DER/PEM encoding errors.
- `ToBase64String` adds `to_base64_string` and `to_pem_base64_string` helpers to `CertReq` for
  base64 output.

## Flows
- Parse a CSR properties string with `CsrProperties::from_properties_str`.
- Parse a CSR properties file with `CsrProperties::parse_csr_config`.
- Build a CSR with `CsrProperties::build` (you provide a signer) or `build_with_rng` (generates a
  new key pair).
- Serialize with `CertReq::to_pem` or `ToBase64String`.

See also: [CSR Guide](../guides/csr.md)
