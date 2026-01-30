# CSR

## Types
- `CsrProperties` holds the required CSR fields parsed from a properties string (common name,
  serial number, org identifiers, country, invoice type, location, business category). It
  validates non-empty fields and country code format.
- `CsrError` covers file I/O, properties parsing, missing keys, invalid subject/SAN construction,
  CSR build failures, key encode/decode errors, and DER/PEM encoding errors.
- `SigningKey` is a crate-owned wrapper over the private key, with `generate`, `from_pem`/`from_der`,
  and `to_pem`/`to_der` helpers.
- `Csr` is a crate-owned wrapper with `to_pem`, `to_der`, `to_base64`, and `to_pem_base64`.

## Flows
- Parse a CSR properties string with `CsrProperties::from_properties_str`.
- Parse a CSR properties file with `CsrProperties::parse_csr_config_file`.
- Generate a key with `SigningKey::generate`.
- Build a CSR with `CsrProperties::build` (you provide the signer).
- Serialize with `Csr::to_pem` / `to_der` or base64 helpers on `Csr`.

See also: [CSR Guide](../guides/csr.md)
