# XML and Schemas

Details about XML handling and schema validation.

## Topics
- XML parsing uses libxml; signing canonicalizes XML (C14N) before hashing and signature
  calculation.
- The default UBL schema is bundled under `assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd`.
  Override via `Config::with_xsd_path` if you need a custom schema.
- Signing inserts template fragments from `assets/templates/ubl_extensions.xml`,
  `assets/templates/cac_signature.xml`, and `assets/templates/qr_reference.xml`.
