# XML and Schemas

Details about XML handling, templates, and bundled schemas.

## Bundled schema
- UBL 2.1 XSD is bundled at:
  `fatoora-core/assets/schemas/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd`.
- Validation always loads this bundled schema (see `invoice-validation`).

## Signing templates
- XML signature fragments are embedded from:
  - `fatoora-core/assets/templates/ubl_extensions.xml`
  - `fatoora-core/assets/templates/cac_signature.xml`
  - `fatoora-core/assets/templates/qr_reference.xml`

## Canonicalization
- Signing canonicalizes XML using C14N 1.1 before hashing and signature generation.
