# API Parity Matrix (Rust -> FFI -> Bindings)

Use this table to track public Rust API items and their equivalents in the FFI and language bindings.

| Rust API item | FFI symbol(s) | Python wrapper |
| --- | --- | --- |
| `Error` | Omitted (errors via `FfiError`) | `FfiError` (binding error type) |
| `config::EnvironmentType` | `FfiEnvironment` | `Environment` |
| `config::EnvironmentParseError` | Omitted (internal) | Omitted |
| `config::Config` | `fatoora_config_new`, `fatoora_config_with_xsd`, `FfiConfig` | `Config` |
| `csr::CsrError` | Omitted (errors via `FfiError`) | Omitted |
| `csr::CsrProperties` | `fatoora_csr_properties_parse`, `FfiCsrProperties` | `CsrProperties` |
| `csr::ToBase64String` | Omitted (internal) | Omitted |
| `invoice::InvoiceBuilder` | `fatoora_invoice_builder_*`, `FfiInvoiceBuilder` | `InvoiceBuilder` |
| `invoice::FinalizedInvoice` | `fatoora_invoice_to_xml`, `FfiFinalizedInvoice` | `Invoice` |
| `invoice::SignedInvoice` | `fatoora_signed_invoice_*`, `FfiSignedInvoice` | `SignedInvoice` |
| `invoice::RequiredInvoiceFields` | Omitted (builder internals) | Omitted |
| `invoice::InvoiceView` | Omitted (internal) | Omitted |
| `invoice::QrCodeError` | Omitted (errors via `FfiError`) | Omitted |
| `invoice::QrPayload` | Omitted (QR string returned) | Omitted |
| `invoice::QrResult` | Omitted (QR string returned) | Omitted |
| `invoice::InvoiceError` | Omitted (errors via `FfiError`) | Omitted |
| `invoice::ValidationError` | Omitted (XML schema only) | Omitted |
| `invoice::ValidationIssue` | Omitted (XML schema only) | Omitted |
| `invoice::InvoiceField` | Omitted (XML schema only) | Omitted |
| `invoice::ValidationKind` | Omitted (XML schema only) | Omitted |
| `invoice::Address` | `FfiAddress`, `fatoora_address_*` | `Address` |
| `invoice::VatId` | `FfiVatId`, `fatoora_vat_id_*` | `VatId` |
| `invoice::OtherId` | `FfiOtherId`, `fatoora_other_id_*` | `OtherId` |
| `invoice::InvoiceNote` | `FfiInvoiceNote`, `fatoora_invoice_note_*` | `InvoiceNote` |
| `invoice::PartyRole` | N/A | N/A |
| `invoice::SellerRole` | N/A | N/A |
| `invoice::BuyerRole` | N/A | N/A |
| `invoice::Party` | `FfiParty`, `fatoora_party_*` | `Party` |
| `invoice::Seller` | `fatoora_invoice_seller`, `fatoora_signed_invoice_seller` | `Invoice.seller`, `SignedInvoice.seller` |
| `invoice::Buyer` | `fatoora_invoice_buyer`, `fatoora_signed_invoice_buyer` | `Invoice.buyer`, `SignedInvoice.buyer` |
| `invoice::InvoiceSubType` | `FfiInvoiceSubType` | `InvoiceSubType` |
| `invoice::OriginalInvoiceRef` | `FfiOriginalInvoiceRef`, `fatoora_original_invoice_ref_*` | `OriginalInvoiceRef` |
| `invoice::InvoiceType` | `FfiInvoiceTypeKind` | `InvoiceTypeKind` |
| `invoice::VatCategory` | `FfiVatCategory` | `VatCategory` |
| `invoice::LineItem` | `fatoora_invoice_line_item_*` | `InvoiceLineItem` |
| `invoice::LineItemFields` | Omitted (construction helper) | Omitted |
| `invoice::LineItemTotalsFields` | Omitted (internal) | Omitted |
| `invoice::LineItemPartsFields` | Omitted (internal) | Omitted |
| `invoice::LineItems` | `fatoora_invoice_line_item_count` | `Invoice.line_items()` |
| `invoice::InvoiceData` | Omitted (use getters) | Omitted |
| `invoice::InvoiceTotalsData` | `fatoora_invoice_totals_*` | `InvoiceTotals` |
| `invoice::sign::SigningError` | Omitted (errors via `FfiError`) | Omitted |
| `invoice::sign::SignedProperties` | Omitted (internal) | Omitted |
| `invoice::sign::InvoiceSigner` | `fatoora_signer_*`, `FfiSigner` | `Signer` |
| `invoice::sign::invoice_hash_base64_from_xml_str` | Omitted (use `*.hash_base64`) | Omitted |
| `invoice::SignedInvoice::signature` | `fatoora_signed_invoice_signature` | `SignedInvoice.signature` |
| `invoice::SignedInvoice::public_key` | `fatoora_signed_invoice_public_key` | `SignedInvoice.public_key` |
| `invoice::sign::SignedProperties::cert_hash` | `fatoora_signed_invoice_cert_hash` | `SignedInvoice.cert_hash` |
| `invoice::sign::SignedProperties::signed_props_hash` | `fatoora_signed_invoice_signed_props_hash` | `SignedInvoice.signed_props_hash` |
| `invoice::sign::SignedProperties::signing_time` | `fatoora_signed_invoice_signing_time` | `SignedInvoice.signing_time` |
| `invoice::validation::ValidationResult` | Omitted (XML schema only) | Omitted |
| `invoice::validation::XmlValidationError` | Omitted (errors via `FfiError`) | Omitted |
| `invoice::validation::validate_xml_invoice_from_str` | `fatoora_validate_xml_str` | `validate_xml_str` |
| `invoice::xml::InvoiceXml` | Omitted (internal) | Omitted |
| `invoice::xml::InvoiceXmlError` | Omitted (errors via `FfiError`) | Omitted |
| `invoice::xml::XmlFormat` | Omitted (internal) | Omitted |
| `invoice::xml::ToXml` | Omitted (exposed via `fatoora_invoice_to_xml`) | Omitted |
| `invoice::xml::parse::ParseError` | Omitted (errors via `FfiError`) | Omitted |
| `invoice::xml::parse::parse_finalized_invoice_xml` | `fatoora_parse_finalized_invoice_xml` | `parse_invoice_xml` |
| `invoice::xml::parse::parse_signed_invoice_xml` | `fatoora_parse_signed_invoice_xml` | `parse_signed_invoice_xml` |
| `api::ZatcaError` | Omitted (errors via `FfiError`) | Omitted |
| `api::TokenScope` | Omitted (internal) | Omitted |
| `api::Compliance` | `FfiCsidCompliance` | `CsidCompliance` |
| `api::Production` | `FfiCsidProduction` | `CsidProduction` |
| `api::ZatcaClient` | `fatoora_zatca_client_new`, `FfiZatcaClient` | `ZatcaClient` |
| `api::ValidationResponse` | `FfiValidationResponse`, `fatoora_validation_response_*` | `ValidationResponse` |
| `api::ValidationResults` | `FfiValidationResults`, `fatoora_validation_results_*` | `ValidationResults` |
| `api::ValidationMessage` | `FfiValidationMessage`, `fatoora_validation_message_*` | `ValidationMessage` |
| `api::MessageList` | `fatoora_validation_results_info_len` + message accessors | `ValidationResults.info_messages()` |
| `api::UnauthorizedResponse` | Omitted (errors via `FfiError`) | Omitted |
| `api::ServerErrorResponse` | Omitted (errors via `FfiError`) | Omitted |
| `api::CsidCredentials` | `fatoora_csid_*`, `FfiCsid*` | `CsidCompliance`/`CsidProduction` |
