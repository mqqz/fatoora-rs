# API Parity Matrix (Rust -> FFI -> Python)

This matrix lists **public Rust core API items** and their FFI/Python coverage. Items intentionally not exposed in FFI are marked as Omitted (intentional). Items without an FFI/Python equivalent are marked Missing (yet to be added). This list is comprehensive for public items in `fatoora-core` as of today.

Status values:
- Done: exposed and in headers/wrappers.
- Omitted (intentional): not exposed by design.
- Missing (yet to be added): public core API with no FFI/Python equivalent.

## Naming Alignment (Rust vs Python vs C)

This table highlights aligned symbol names across layers.

| Rust | Python | C (FFI) |
| --- | --- | --- |
| `Config::env` | `Config.env()` | `fatoora_config_env` |
| `CsrProperties::parse_csr_config` | `CsrProperties.parse_csr_config` | `fatoora_csr_properties_parse_csr_config` |
| `CsrProperties::parse_csr_config_file` | `CsrProperties.parse_csr_config_file` | `fatoora_csr_properties_parse_csr_config_file` |
| `ZatcaClient::check_invoice_compliance` | `ZatcaClient.check_invoice_compliance` | `fatoora_zatca_check_invoice_compliance` |
| `CsidCredentials::binary_security_token` | `CsidCompliance.binary_security_token()` / `CsidProduction.binary_security_token()` | `fatoora_csid_*_binary_security_token` |
| `SignedInvoice::qr_code` | `SignedInvoice.qr_code()` | `fatoora_signed_invoice_qr_code` |
| `SignedInvoice::to_xml_base64` | `SignedInvoice.to_xml_base64()` | `fatoora_signed_invoice_to_xml_base64` |
| `InvoiceBuilder::flags` | `InvoiceBuilder.flags(...)` | `fatoora_invoice_builder_flags` |
| `InvoiceBuilder::invoice_level_charge` | `InvoiceBuilder.invoice_level_charge(...)` | `fatoora_invoice_builder_invoice_level_charge` |
| `InvoiceBuilder::invoice_level_discount` | `InvoiceBuilder.invoice_level_discount(...)` | `fatoora_invoice_builder_invoice_level_discount` |
| `InvoiceBuilder::allowance_reason` | `InvoiceBuilder.allowance_reason(...)` | `fatoora_invoice_builder_allowance_reason` |

## config
| Core public API item | FFI symbol(s) | Python symbol | Status | Notes |
| --- | --- | --- | --- | --- |
| `EnvironmentType` | `FfiEnvironment` | `Environment` | Done |  |
| `EnvironmentType::as_str` | — | — | Omitted (intentional) | FFI uses enums directly. |
| `EnvironmentType::endpoint_url` | — | — | Omitted (intentional) | Not exposed to bindings. |
| `EnvironmentParseError` | — | — | Omitted (intentional) | Errors normalized via `FfiErrorKind`. |
| `Config::new` | `fatoora_config_new` | `Config` | Done |  |
| `Config::default` | — | — | Omitted (intentional) | `Config` defaults to NonProduction in Rust. |
| `Config::env` | `fatoora_config_env` | `Config.env` | Done | Python method reads from FFI handle. |

## csr
| Core public API item | FFI symbol(s) | Python symbol | Status | Notes |
| --- | --- | --- | --- | --- |
| `CsrError` | — | — | Omitted (intentional) | Errors normalized via `FfiErrorKind`. |
| `SigningKey::generate` | `fatoora_signing_key_generate` | `SigningKey.generate` | Done |  |
| `SigningKey::from_pem` | `fatoora_signing_key_from_pem` | `SigningKey.from_pem` | Done |  |
| `SigningKey::from_der` | `fatoora_signing_key_from_der` | `SigningKey.from_der` | Done |  |
| `SigningKey::to_pem` | `fatoora_signing_key_to_pem` | `SigningKey.to_pem` | Done |  |
| `SigningKey::to_der` | `fatoora_signing_key_to_der` | `SigningKey.to_der` | Done | Uses `FfiBytes`. |
| `Csr::from_der` | `fatoora_csr_from_der` | `Csr.from_der` | Done |  |
| `Csr::to_der` | `fatoora_csr_to_der` | `Csr.to_der` | Done |  |
| `Csr::to_pem` | `fatoora_csr_to_pem` | `Csr.to_pem` | Done |  |
| `Csr::to_base64` | `fatoora_csr_to_base64` | `Csr.to_base64` | Done |  |
| `Csr::to_pem_base64` | `fatoora_csr_to_pem_base64` | `Csr.to_pem_base64` | Done |  |
| `Csr::subject_string` | `fatoora_csr_subject_string` | `Csr.subject_string` | Done |  |
| `Csr::extension_values_der` | `fatoora_csr_extension_values_der` | `Csr.extension_values_der` | Done |  |
| `CsrProperties::from_properties_str` | `fatoora_csr_properties_from_str` | `CsrProperties.from_properties_str` | Done |  |
| `CsrProperties::parse_csr_config` | `fatoora_csr_properties_parse_csr_config` | `CsrProperties.parse_csr_config` | Done |  |
| `CsrProperties::parse_csr_config_file` | `fatoora_csr_properties_parse_csr_config_file` | `CsrProperties.parse_csr_config_file` | Done |  |
| `CsrProperties::build` | `fatoora_csr_build` | `CsrProperties.build` | Done |  |

## invoice (model types)
| Core public API item | FFI symbol(s) | Python symbol | Status | Notes |
| --- | --- | --- | --- | --- |
| `InvoiceError` | — | — | Omitted (intentional) | Errors normalized via `FfiErrorKind`. |
| `ValidationError` | — | — | Omitted (intentional) | Internal validation details. |
| `ValidationIssue` | — | — | Omitted (intentional) | Internal validation details. |
| `InvoiceField` | — | — | Omitted (intentional) | Internal validation details. |
| `ValidationKind` | — | — | Omitted (intentional) | Internal validation details. |
| `CountryCode` + `parse/as_str` | — | — | Omitted (intentional) | FFI uses validated strings. |
| `CurrencyCode` + `parse/as_str` | — | — | Omitted (intentional) | FFI uses validated strings. |
| `InvoiceTimestamp` + `parse/as_str` | — | — | Omitted (intentional) | FFI uses validated strings. |
| `InvoiceDate` + `parse/as_str` | — | — | Omitted (intentional) | FFI uses validated strings. |
| `Address` accessors | `fatoora_address_*` | `Address.*` | Done |  |
| `VatId::parse/as_str` | `fatoora_vat_id_*` | `VatId.value` | Done |  |
| `OtherId::{new,with_scheme,as_str,scheme_id}` | `fatoora_other_id_*` | `OtherId.value/scheme` | Done | Constructors via builder only. |
| `InvoiceNote::{new,language,text}` | `fatoora_invoice_note_*` | `InvoiceNote.language/text` | Done | Constructors via builder only. |
| `PartyRole` | — | — | Omitted (intentional) | Marker trait only. |
| `SellerRole` / `BuyerRole` | — | — | Omitted (intentional) | Marker types only. |
| `Party::{new,name,address,vat_id,other_id}` | `fatoora_party_*` | `Party.*` | Done | Constructors via builder only. |
| `InvoiceSubType` | `FfiInvoiceSubType` | `InvoiceSubType` | Done |  |
| `OriginalInvoiceRef` + accessors | `fatoora_original_invoice_ref_*` | `OriginalInvoiceRef.*` | Done |  |
| `InvoiceType` | `FfiInvoiceTypeKind`/`FfiInvoiceSubType` + accessors | `InvoiceTypeKind`/`InvoiceSubType` | Done |  |
| `InvoiceType::is_simplified` | — | — | Omitted (intentional) | Can be derived from kind/subtype in bindings. |
| `VatCategory` | `FfiVatCategory` | `VatCategory` | Done |  |
| `LineItem::{new,from_totals,try_from_parts}` | — | — | Omitted (intentional) | Constructed via builder setters in FFI/Python. |
| `LineItem` accessors | `fatoora_*_invoice_line_item_*` | `InvoiceLineItem` | Done |  |
| `InvoiceFlags` | `FfiInvoiceFlag` + `fatoora_*_flags` | `InvoiceFlag` | Done | Exposed as bitset. |
| `InvoiceData` | — | — | Omitted (intentional) | Use per-field accessors on `FinalizedInvoice`/`SignedInvoice`. |
| `InvoiceData::invoice_type` | `fatoora_*_invoice_type_kind/sub_type` | `FinalizedInvoice.invoice_type_kind/sub_type`, `SignedInvoice.invoice_type_kind/sub_type` | Done |  |
| `InvoiceData::id` | `fatoora_invoice_id` / `fatoora_signed_invoice_id` | `FinalizedInvoice.id` / `SignedInvoice.id` | Done |  |
| `InvoiceData::uuid` | `fatoora_invoice_uuid` / `fatoora_signed_invoice_uuid` | `FinalizedInvoice.uuid` / `SignedInvoice.uuid` | Done |  |
| `InvoiceData::issue_datetime` | `fatoora_invoice_issue_datetime` / `fatoora_signed_invoice_issue_datetime` | `FinalizedInvoice.issue_datetime` / `SignedInvoice.issue_datetime` | Done |  |
| `InvoiceData::currency` | `fatoora_invoice_currency` / `fatoora_signed_invoice_currency` | `FinalizedInvoice.currency` / `SignedInvoice.currency` | Done |  |
| `InvoiceData::previous_invoice_hash` | `fatoora_invoice_previous_hash` / `fatoora_signed_invoice_previous_hash` | `FinalizedInvoice.previous_invoice_hash` / `SignedInvoice.previous_invoice_hash` | Done |  |
| `InvoiceData::invoice_counter` | `fatoora_invoice_counter` / `fatoora_signed_invoice_counter` | `FinalizedInvoice.invoice_counter` / `SignedInvoice.invoice_counter` | Done |  |
| `InvoiceData::note` | `fatoora_invoice_note` / `fatoora_signed_invoice_note` | `FinalizedInvoice.note`, `SignedInvoice.note` | Done |  |
| `InvoiceData::seller` | `fatoora_invoice_seller` / `fatoora_signed_invoice_seller` | `FinalizedInvoice.seller`, `SignedInvoice.seller` | Done |  |
| `InvoiceData::buyer` | `fatoora_invoice_buyer` / `fatoora_signed_invoice_buyer` | `FinalizedInvoice.buyer`, `SignedInvoice.buyer` | Done |  |
| `InvoiceData::line_items` | `fatoora_*_invoice_line_item_*` + count | `FinalizedInvoice.line_items`, `SignedInvoice.line_items` | Done |  |
| `InvoiceData::payment_means_code` | `fatoora_invoice_payment_means_code` / `fatoora_signed_invoice_payment_means_code` | `FinalizedInvoice.payment_means_code` / `SignedInvoice.payment_means_code` | Done |  |
| `InvoiceData::vat_category` | `fatoora_invoice_vat_category` / `fatoora_signed_invoice_vat_category` | `FinalizedInvoice.vat_category` / `SignedInvoice.vat_category` | Done |  |
| `InvoiceData::flags` | `fatoora_invoice_flags` / `fatoora_signed_invoice_flags` | `FinalizedInvoice.flags/flags_raw`, `SignedInvoice.flags/flags_raw` | Done |  |
| `InvoiceData::is_*` helpers | — | — | Omitted (intentional) | Derivable from flags. |
| `InvoiceData::invoice_level_charge` | `fatoora_invoice_level_charge` / `fatoora_signed_invoice_level_charge` | `FinalizedInvoice.invoice_level_charge` / `SignedInvoice.invoice_level_charge` | Done |  |
| `InvoiceData::invoice_level_discount` | `fatoora_invoice_level_discount` / `fatoora_signed_invoice_level_discount` | `FinalizedInvoice.invoice_level_discount` / `SignedInvoice.invoice_level_discount` | Done |  |
| `InvoiceData::allowance_reason` | `fatoora_invoice_allowance_reason` / `fatoora_signed_invoice_allowance_reason` | `FinalizedInvoice.allowance_reason` / `SignedInvoice.allowance_reason` | Done |  |
| `InvoiceTotalsData` accessors | `fatoora_*_invoice_totals_*` | `InvoiceTotals` | Done |  |

## invoice (builder + finalized/signed)
| Core public API item | FFI symbol(s) | Python symbol | Status | Notes |
| --- | --- | --- | --- | --- |
| `InvoiceBuilder::new` | `fatoora_invoice_builder_new` | `InvoiceBuilder.new` | Done |  |
| `InvoiceBuilder::set_id` | `fatoora_invoice_builder_set_id` | `InvoiceBuilder.set_id` | Done |  |
| `InvoiceBuilder::set_uuid` | `fatoora_invoice_builder_set_uuid` | `InvoiceBuilder.set_uuid` | Done |  |
| `InvoiceBuilder::set_issue_datetime` | `fatoora_invoice_builder_set_issue_datetime` | `InvoiceBuilder.set_issue_datetime` | Done |  |
| `InvoiceBuilder::set_currency` | `fatoora_invoice_builder_set_currency` | `InvoiceBuilder.set_currency` | Done |  |
| `InvoiceBuilder::set_previous_invoice_hash` | `fatoora_invoice_builder_set_previous_hash` | `InvoiceBuilder.set_previous_invoice_hash` | Done |  |
| `InvoiceBuilder::set_invoice_counter` | `fatoora_invoice_builder_set_invoice_counter` | `InvoiceBuilder.set_invoice_counter` | Done |  |
| `InvoiceBuilder::set_seller` | `fatoora_invoice_builder_set_seller` | `InvoiceBuilder.set_seller` | Done |  |
| `InvoiceBuilder::set_payment_means_code` | `fatoora_invoice_builder_set_payment_means_code` | `InvoiceBuilder.set_payment_means_code` | Done |  |
| `InvoiceBuilder::set_vat_category` | `fatoora_invoice_builder_set_vat_category` | `InvoiceBuilder.set_vat_category` | Done |  |
| `InvoiceBuilder::set_buyer` | `fatoora_invoice_builder_set_buyer` | `InvoiceBuilder.set_buyer` | Done |  |
| `InvoiceBuilder::set_note` | `fatoora_invoice_builder_set_note` | `InvoiceBuilder.set_note` | Done |  |
| `InvoiceBuilder::set_allowance` | `fatoora_invoice_builder_set_allowance` | `InvoiceBuilder.set_allowance` | Done |  |
| `InvoiceBuilder::add_line_item` | `fatoora_invoice_builder_add_line_item` | `InvoiceBuilder.add_line_item` | Done |  |
| `InvoiceBuilder::flags` | `fatoora_invoice_builder_flags` | `InvoiceBuilder.flags` | Done | Rust uses `flags(...)` setter. |
| `InvoiceBuilder::invoice_level_charge` | `fatoora_invoice_builder_invoice_level_charge` | `InvoiceBuilder.invoice_level_charge` | Done |  |
| `InvoiceBuilder::invoice_level_discount` | `fatoora_invoice_builder_invoice_level_discount` | `InvoiceBuilder.invoice_level_discount` | Done |  |
| `InvoiceBuilder::allowance_reason` | `fatoora_invoice_builder_allowance_reason` | `InvoiceBuilder.allowance_reason` | Done |  |
| `InvoiceBuilder::build` | `fatoora_invoice_builder_build` | `InvoiceBuilder.build` | Done |  |
| `FinalizedInvoice::data` | `fatoora_invoice_*` accessors | — | Done | Accessed via per-field FFI getters. |
| `FinalizedInvoice::totals` | `fatoora_invoice_totals_*` | `FinalizedInvoice.totals` | Done |  |
| `FinalizedInvoice::hash_base64` | `fatoora_invoice_hash_base64` | `FinalizedInvoice.hash_base64` | Done |  |
| `FinalizedInvoice::sign` | `fatoora_invoice_sign` | `FinalizedInvoice.sign` | Done |  |
| `SignedInvoice::data` | `fatoora_signed_invoice_*` accessors | — | Done | Accessed via per-field FFI getters. |
| `SignedInvoice::totals` | `fatoora_signed_invoice_totals_*` | `SignedInvoice.totals` | Done |  |
| `SignedInvoice::signed_properties` | — | — | Omitted (intentional) | Access via signed-only getters. |
| `SignedInvoice::qr_code` | `fatoora_signed_invoice_qr_code` | `SignedInvoice.qr_code` | Done |  |
| `SignedInvoice::xml` | `fatoora_signed_invoice_xml` | `SignedInvoice.xml` | Done |  |
| `SignedInvoice::uuid` | `fatoora_signed_invoice_uuid` | `SignedInvoice.uuid` | Done |  |
| `SignedInvoice::invoice_hash` | `fatoora_signed_invoice_hash` | `SignedInvoice.invoice_hash` | Done |  |
| `SignedInvoice::hash_base64` | `fatoora_signed_invoice_hash_base64` | `SignedInvoice.hash_base64` | Done |  |
| `SignedInvoice::signature` | `fatoora_signed_invoice_signature` | `SignedInvoice.signature` | Done |  |
| `SignedInvoice::public_key` | `fatoora_signed_invoice_public_key` | `SignedInvoice.public_key` | Done |  |
| `SignedInvoice::zatca_key_signature` | `fatoora_signed_invoice_zatca_key_signature` | `SignedInvoice.zatca_key_signature` | Done |  |
| `SignedInvoice::to_xml_base64` | `fatoora_signed_invoice_to_xml_base64` | `SignedInvoice.to_xml_base64` | Done |  |
| `InvoiceView` | — | — | Omitted (intentional) | Internal trait. |

## invoice::sign
| Core public API item | FFI symbol(s) | Python symbol | Status | Notes |
| --- | --- | --- | --- | --- |
| `SigningError` | — | — | Omitted (intentional) | Errors normalized via `FfiErrorKind`. |
| `SignedProperties::invoice_hash` | `fatoora_signed_invoice_hash` | `SignedInvoice.invoice_hash` | Done | Accessed via signed invoice getters. |
| `SignedProperties::signature` | `fatoora_signed_invoice_signature` | `SignedInvoice.signature` | Done | Accessed via signed invoice getters. |
| `SignedProperties::public_key` | `fatoora_signed_invoice_public_key` | `SignedInvoice.public_key` | Done | Accessed via signed invoice getters. |
| `SignedProperties::zatca_key_signature` | `fatoora_signed_invoice_zatca_key_signature` | `SignedInvoice.zatca_key_signature` | Done | Accessed via signed invoice getters. |
| `SignedProperties::cert_hash` | `fatoora_signed_invoice_cert_hash` | `SignedInvoice.cert_hash` | Done | Accessed via signed invoice getters. |
| `SignedProperties::signed_props_hash` | `fatoora_signed_invoice_signed_props_hash` | `SignedInvoice.signed_props_hash` | Done | Accessed via signed invoice getters. |
| `SignedProperties::signing_time` | `fatoora_signed_invoice_signing_time` | `SignedInvoice.signing_time` | Done | Accessed via signed invoice getters. |
| `SignedProperties::issuer` | — | — | Missing (yet to be added) | Not exposed in bindings. |
| `SignedProperties::serial` | — | — | Missing (yet to be added) | Not exposed in bindings. |
| `InvoiceSigner::from_der` | `fatoora_signer_from_der` | `Signer.from_der` | Done |  |
| `InvoiceSigner::from_pem` | `fatoora_signer_from_pem` | `Signer.from_pem` | Done |  |
| `InvoiceSigner::sign_xml` | — | — | Missing (yet to be added) |  |
| `InvoiceSigner::certificate` | — | — | Omitted (intentional) | Returns external `x509_cert::Certificate`. |
| `invoice_hash_base64_from_xml_str` | — | — | Missing (yet to be added) |  |

## invoice::xml
| Core public API item | FFI symbol(s) | Python symbol | Status | Notes |
| --- | --- | --- | --- | --- |
| `InvoiceXml` | — | — | Omitted (intentional) | Internal XML model. |
| `InvoiceXmlError` | — | — | Omitted (intentional) | Errors normalized via `FfiErrorKind`. |
| `XmlFormat` | — | — | Omitted (intentional) | Internal XML formatting. |
| `ToXml` | — | — | Omitted (intentional) | Exposed via `fatoora_invoice_to_xml`. |

## invoice::xml::parse
| Core public API item | FFI symbol(s) | Python symbol | Status | Notes |
| --- | --- | --- | --- | --- |
| `ParseError` | — | — | Omitted (intentional) | Errors normalized via `FfiErrorKind`. |
| `parse_finalized_invoice_xml` | `fatoora_parse_finalized_invoice_xml` | `parse_finalized_invoice_xml` | Done |  |
| `parse_finalized_invoice_xml_file` | `fatoora_parse_finalized_invoice_xml_file` | `parse_finalized_invoice_xml_file` | Done |  |
| `parse_signed_invoice_xml` | `fatoora_parse_signed_invoice_xml` | `parse_signed_invoice_xml` | Done |  |
| `parse_signed_invoice_xml_file` | `fatoora_parse_signed_invoice_xml_file` | `parse_signed_invoice_xml_file` | Done |  |

## invoice::validation
| Core public API item | FFI symbol(s) | Python symbol | Status | Notes |
| --- | --- | --- | --- | --- |
| `ValidationResult` | — | — | Omitted (intentional) | FFI only exposes boolean result. |
| `XmlValidationError` | — | — | Omitted (intentional) | Errors normalized via `FfiErrorKind`. |
| `validate_xml_invoice_from_str` | `fatoora_validate_xml_invoice_from_str` | `validate_xml_invoice_from_str` | Done |  |

## invoice::qr
| Core public API item | FFI symbol(s) | Python symbol | Status | Notes |
| --- | --- | --- | --- | --- |
| `QrCodeError` | — | — | Omitted (intentional) | Errors normalized via `FfiErrorKind`. |
| `QrResult` | — | — | Omitted (intentional) | QR exposed as string. |
| `QrPayload` | — | — | Omitted (intentional) | QR exposed as string. |

## api
| Core public API item | FFI symbol(s) | Python symbol | Status | Notes |
| --- | --- | --- | --- | --- |
| `ZatcaError` | — | — | Omitted (intentional) | Errors normalized via `FfiErrorKind`. |
| `TokenScope` | — | — | Omitted (intentional) | Internal marker trait. |
| `Compliance` | — | — | Omitted (intentional) | Marker type only. |
| `Production` | — | — | Omitted (intentional) | Marker type only. |
| `ValidationResponse::{validation_results,reporting_status,clearance_status,qr_seller_status,qr_buyer_status}` | `fatoora_validation_response_*` | `ValidationResponse.*` | Done |  |
| `ValidationResults::{info_messages,warning_messages,error_messages,status}` | `fatoora_validation_results_*` | `ValidationResults.*` | Done |  |
| `ValidationMessage::{message_type,code,category,message,status}` | `fatoora_validation_message_*` | `ValidationMessage.*` | Done |  |
| `MessageList` | — | — | Omitted (intentional) | Flattened into FFI accessors. |
| `UnauthorizedResponse` | — | — | Omitted (intentional) | Internal error body. |
| `ServerErrorResponse` | — | — | Omitted (intentional) | Internal error body. |
| `CsidCredentials::new` | `fatoora_csid_compliance_new` / `fatoora_csid_production_new` | `CsidCompliance.new` / `CsidProduction.new` | Done | Separate handle types. |
| `CsidCredentials::env` | `fatoora_csid_*_env` | `CsidCompliance.env` / `CsidProduction.env` | Done |  |
| `CsidCredentials::request_id` | `fatoora_csid_*_request_id` | `CsidCompliance.request_id` / `CsidProduction.request_id` | Done | `request_id` is a string; empty string is the sentinel. |
| `CsidCredentials::binary_security_token` | `fatoora_csid_*_binary_security_token` | `CsidCompliance.binary_security_token` / `CsidProduction.binary_security_token` | Done |  |
| `CsidCredentials::secret` | `fatoora_csid_*_secret` | `CsidCompliance.secret` / `CsidProduction.secret` | Done |  |
| `ZatcaClient::new` | `fatoora_zatca_client_new` | `ZatcaClient.__init__` | Done |  |
| `ZatcaClient::check_invoice_compliance` | `fatoora_zatca_check_invoice_compliance` | `ZatcaClient.check_invoice_compliance` | Done |  |
| `ZatcaClient::report_simplified_invoice` | `fatoora_zatca_report_simplified_invoice` | `ZatcaClient.report_simplified_invoice` | Done |  |
| `ZatcaClient::clear_standard_invoice` | `fatoora_zatca_clear_standard_invoice` | `ZatcaClient.clear_standard_invoice` | Done |  |
| `ZatcaClient::post_csr_for_ccsid` | `fatoora_zatca_post_csr_for_ccsid` | `ZatcaClient.post_csr_for_ccsid` | Done |  |
| `ZatcaClient::post_ccsid_for_pcsid` | `fatoora_zatca_post_ccsid_for_pcsid` | `ZatcaClient.post_ccsid_for_pcsid` | Done |  |
| `ZatcaClient::renew_csid` | `fatoora_zatca_renew_csid` | `ZatcaClient.renew_csid` | Done |  |
