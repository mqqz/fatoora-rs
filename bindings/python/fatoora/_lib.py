from __future__ import annotations

import os
from pathlib import Path

from cffi import FFI

_CDEF_PREAMBLE = """
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef signed long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long size_t;
typedef unsigned long uintptr_t;
typedef _Bool bool;
"""


_CDEF = """
typedef struct { void* ptr; } FfiConfig;
typedef struct { void* ptr; } FfiInvoiceBuilder;
typedef struct { void* ptr; } FfiFinalizedInvoice;
typedef struct { void* ptr; } FfiSignedInvoice;
typedef struct { void* ptr; } FfiSigner;
typedef struct { char* ptr; } FfiString;
typedef struct { void* ptr; } FfiCsrProperties;
typedef struct { void* ptr; } FfiCsr;
typedef struct { void* ptr; } FfiSigningKey;
typedef struct { void* ptr; } FfiZatcaClient;
typedef struct { void* ptr; } FfiCsidCompliance;
typedef struct { void* ptr; } FfiCsidProduction;
typedef struct { void* ptr; } FfiValidationResponse;
typedef struct { void* ptr; } FfiValidationResults;
typedef struct { void* ptr; } FfiValidationMessage;
typedef struct { void* ptr; } FfiAddress;
typedef struct { void* ptr; } FfiParty;
typedef struct { void* ptr; } FfiVatId;
typedef struct { void* ptr; } FfiOtherId;
typedef struct { void* ptr; } FfiInvoiceNote;
typedef struct { void* ptr; } FfiOriginalInvoiceRef;
typedef struct { unsigned char* ptr; uintptr_t len; } FfiBytes;
typedef struct { FfiBytes* ptr; uintptr_t len; } FfiBytesList;
typedef struct { int code; char* message; } FfiError;

typedef struct { _Bool ok; FfiInvoiceBuilder value; FfiError* error; } FfiResult_FfiInvoiceBuilder;
typedef struct { _Bool ok; FfiFinalizedInvoice value; FfiError* error; } FfiResult_FfiFinalizedInvoice;
typedef struct { _Bool ok; FfiSignedInvoice value; FfiError* error; } FfiResult_FfiSignedInvoice;
typedef struct { _Bool ok; FfiSigner value; FfiError* error; } FfiResult_FfiSigner;
typedef struct { _Bool ok; FfiString value; FfiError* error; } FfiResult_FfiString;
typedef struct { _Bool ok; FfiCsrProperties value; FfiError* error; } FfiResult_FfiCsrProperties;
typedef struct { _Bool ok; FfiCsr value; FfiError* error; } FfiResult_FfiCsr;
typedef struct { _Bool ok; FfiSigningKey value; FfiError* error; } FfiResult_FfiSigningKey;
typedef struct { _Bool ok; FfiZatcaClient value; FfiError* error; } FfiResult_FfiZatcaClient;
typedef struct { _Bool ok; FfiCsidCompliance value; FfiError* error; } FfiResult_FfiCsidCompliance;
typedef struct { _Bool ok; FfiCsidProduction value; FfiError* error; } FfiResult_FfiCsidProduction;
typedef struct { _Bool ok; FfiValidationResponse value; FfiError* error; } FfiResult_FfiValidationResponse;
typedef struct { _Bool ok; FfiValidationResults value; FfiError* error; } FfiResult_FfiValidationResults;
typedef struct { _Bool ok; FfiValidationMessage value; FfiError* error; } FfiResult_FfiValidationMessage;
typedef struct { _Bool ok; FfiAddress value; FfiError* error; } FfiResult_FfiAddress;
typedef struct { _Bool ok; FfiParty value; FfiError* error; } FfiResult_FfiParty;
typedef struct { _Bool ok; FfiVatId value; FfiError* error; } FfiResult_FfiVatId;
typedef struct { _Bool ok; FfiOtherId value; FfiError* error; } FfiResult_FfiOtherId;
typedef struct { _Bool ok; FfiInvoiceNote value; FfiError* error; } FfiResult_FfiInvoiceNote;
typedef struct { _Bool ok; FfiOriginalInvoiceRef value; FfiError* error; } FfiResult_FfiOriginalInvoiceRef;
typedef struct { _Bool ok; FfiBytes value; FfiError* error; } FfiResult_FfiBytes;
typedef struct { _Bool ok; FfiBytesList value; FfiError* error; } FfiResult_FfiBytesList;
typedef struct { _Bool ok; int value; FfiError* error; } FfiResult_FfiEnvironment;
typedef struct { _Bool ok; int value; FfiError* error; } FfiResult_FfiInvoiceTypeKind;
typedef struct { _Bool ok; int value; FfiError* error; } FfiResult_FfiInvoiceSubType;
typedef struct { _Bool ok; int value; FfiError* error; } FfiResult_FfiVatCategory;
typedef struct { _Bool ok; _Bool value; FfiError* error; } FfiResult_bool;
typedef struct { _Bool ok; unsigned long long value; FfiError* error; } FfiResult_u64;
typedef struct { _Bool ok; unsigned char value; FfiError* error; } FfiResult_u8;
typedef struct { _Bool ok; double value; FfiError* error; } FfiResult_f64;

void fatoora_error_free(FfiError* error);
int fatoora_error_code(FfiError* error);
FfiString fatoora_error_message(FfiError* error);
void fatoora_string_free(FfiString value);
void fatoora_bytes_free(FfiBytes value);
void fatoora_bytes_list_free(FfiBytesList value);

FfiConfig* fatoora_config_new(int env);
FfiResult_FfiEnvironment fatoora_config_env(FfiConfig* cfg);
void fatoora_config_free(FfiConfig* cfg);

FfiResult_FfiCsrProperties fatoora_csr_properties_parse(const char* properties);
FfiResult_FfiCsrProperties fatoora_csr_properties_parse_file(const char* path);
FfiResult_FfiCsrProperties fatoora_csr_properties_from_str(const char* properties);
void fatoora_csr_properties_free(FfiCsrProperties* props);

FfiResult_FfiSigningKey fatoora_signing_key_from_pem(const char* pem);
FfiResult_FfiSigningKey fatoora_signing_key_from_der(const unsigned char* der, uintptr_t len);
FfiResult_FfiSigningKey fatoora_signing_key_generate(void);
FfiResult_FfiString fatoora_signing_key_to_pem(FfiSigningKey* key);
FfiResult_FfiBytes fatoora_signing_key_to_der(FfiSigningKey* key);
void fatoora_signing_key_free(FfiSigningKey* key);

FfiResult_FfiCsr fatoora_csr_from_der(const unsigned char* der, uintptr_t len);
FfiResult_FfiCsr fatoora_csr_build(FfiCsrProperties* props, FfiSigningKey* key, int env);
FfiResult_FfiString fatoora_csr_to_base64(FfiCsr* csr);
FfiResult_FfiString fatoora_csr_to_pem_base64(FfiCsr* csr);
FfiResult_FfiBytes fatoora_csr_to_der(FfiCsr* csr);
FfiResult_FfiString fatoora_csr_to_pem(FfiCsr* csr);
FfiResult_FfiString fatoora_csr_subject_string(FfiCsr* csr);
FfiResult_FfiBytesList fatoora_csr_extension_values_der(FfiCsr* csr);
void fatoora_csr_free(FfiCsr* csr);

FfiResult_FfiZatcaClient fatoora_zatca_client_new(FfiConfig* cfg);
void fatoora_zatca_client_free(FfiZatcaClient* client);

FfiResult_FfiCsidCompliance fatoora_csid_compliance_new(
    int env,
    const char* request_id,
    const char* token,
    const char* secret
);
FfiResult_FfiCsidProduction fatoora_csid_production_new(
    int env,
    const char* request_id,
    const char* token,
    const char* secret
);
FfiResult_FfiString fatoora_csid_compliance_request_id(FfiCsidCompliance* creds);
FfiResult_FfiString fatoora_csid_production_request_id(FfiCsidProduction* creds);
FfiResult_FfiEnvironment fatoora_csid_compliance_env(FfiCsidCompliance* creds);
FfiResult_FfiEnvironment fatoora_csid_production_env(FfiCsidProduction* creds);
FfiResult_FfiString fatoora_csid_compliance_token(FfiCsidCompliance* creds);
FfiResult_FfiString fatoora_csid_compliance_secret(FfiCsidCompliance* creds);
FfiResult_FfiString fatoora_csid_production_token(FfiCsidProduction* creds);
FfiResult_FfiString fatoora_csid_production_secret(FfiCsidProduction* creds);
void fatoora_csid_compliance_free(FfiCsidCompliance* creds);
void fatoora_csid_production_free(FfiCsidProduction* creds);

FfiResult_FfiCsidCompliance fatoora_zatca_post_csr_for_ccsid(
    FfiZatcaClient* client,
    FfiCsr* csr,
    const char* otp
);
FfiResult_FfiCsidProduction fatoora_zatca_post_ccsid_for_pcsid(
    FfiZatcaClient* client,
    FfiCsidCompliance* ccsid
);
FfiResult_FfiCsidProduction fatoora_zatca_renew_csid(
    FfiZatcaClient* client,
    FfiCsidProduction* pcsid,
    FfiCsr* csr,
    const char* otp,
    const char* accept_language
);
FfiResult_FfiValidationResponse fatoora_zatca_check_compliance(
    FfiZatcaClient* client,
    FfiSignedInvoice* invoice,
    FfiCsidCompliance* ccsid
);
FfiResult_FfiValidationResponse fatoora_zatca_report_simplified_invoice(
    FfiZatcaClient* client,
    FfiSignedInvoice* invoice,
    FfiCsidProduction* pcsid,
    _Bool clearance_status,
    const char* accept_language
);
FfiResult_FfiValidationResponse fatoora_zatca_clear_standard_invoice(
    FfiZatcaClient* client,
    FfiSignedInvoice* invoice,
    FfiCsidProduction* pcsid,
    _Bool clearance_status,
    const char* accept_language
);

void fatoora_validation_response_free(FfiValidationResponse* response);
FfiResult_FfiString fatoora_validation_response_reporting_status(FfiValidationResponse* response);
FfiResult_FfiString fatoora_validation_response_clearance_status(FfiValidationResponse* response);
FfiResult_FfiString fatoora_validation_response_qr_seller_status(FfiValidationResponse* response);
FfiResult_FfiString fatoora_validation_response_qr_buyer_status(FfiValidationResponse* response);
FfiResult_FfiValidationResults fatoora_validation_response_results(FfiValidationResponse* response);

void fatoora_validation_results_free(FfiValidationResults* results);
FfiResult_FfiString fatoora_validation_results_status(FfiValidationResults* results);
FfiResult_u64 fatoora_validation_results_info_len(FfiValidationResults* results);
FfiResult_u64 fatoora_validation_results_warning_len(FfiValidationResults* results);
FfiResult_u64 fatoora_validation_results_error_len(FfiValidationResults* results);
FfiResult_FfiValidationMessage fatoora_validation_results_info_message(FfiValidationResults* results, unsigned long long index);
FfiResult_FfiValidationMessage fatoora_validation_results_warning_message(FfiValidationResults* results, unsigned long long index);
FfiResult_FfiValidationMessage fatoora_validation_results_error_message(FfiValidationResults* results, unsigned long long index);

void fatoora_validation_message_free(FfiValidationMessage* message);
FfiResult_FfiString fatoora_validation_message_type(FfiValidationMessage* message);
FfiResult_FfiString fatoora_validation_message_code(FfiValidationMessage* message);
FfiResult_FfiString fatoora_validation_message_category(FfiValidationMessage* message);
FfiResult_FfiString fatoora_validation_message_text(FfiValidationMessage* message);
FfiResult_FfiString fatoora_validation_message_status(FfiValidationMessage* message);

FfiResult_bool fatoora_validate_xml_str(FfiConfig* cfg, const char* xml);

FfiResult_FfiInvoiceBuilder fatoora_invoice_builder_new(
    int invoice_type_kind,
    int invoice_sub_type,
    const char* original_invoice_id,
    const char* original_invoice_uuid,
    const char* original_invoice_issue_date,
    const char* original_invoice_reason
);

FfiResult_bool fatoora_invoice_builder_set_id(FfiInvoiceBuilder* builder, const char* id);
FfiResult_bool fatoora_invoice_builder_set_uuid(FfiInvoiceBuilder* builder, const char* uuid);
FfiResult_bool fatoora_invoice_builder_set_issue_datetime(FfiInvoiceBuilder* builder, const char* issue_timestamp);
FfiResult_bool fatoora_invoice_builder_set_currency(FfiInvoiceBuilder* builder, const char* currency_code);
FfiResult_bool fatoora_invoice_builder_set_previous_hash(FfiInvoiceBuilder* builder, const char* hash);
FfiResult_bool fatoora_invoice_builder_set_invoice_counter(FfiInvoiceBuilder* builder, unsigned long long counter);
FfiResult_bool fatoora_invoice_builder_set_payment_means_code(FfiInvoiceBuilder* builder, const char* payment_means_code);
FfiResult_bool fatoora_invoice_builder_set_vat_category(FfiInvoiceBuilder* builder, int vat_category);
FfiResult_bool fatoora_invoice_builder_set_seller(
    FfiInvoiceBuilder* builder,
    const char* name,
    const char* country_code,
    const char* city,
    const char* street,
    const char* additional_street,
    const char* building_number,
    const char* additional_number,
    const char* postal_code,
    const char* subdivision,
    const char* district,
    const char* vat_id,
    const char* other_id_value,
    const char* other_id_scheme
);

FfiResult_bool fatoora_invoice_builder_add_line_item(
    FfiInvoiceBuilder* builder,
    const char* description,
    double quantity,
    const char* unit_code,
    double unit_price,
    double vat_rate,
    int vat_category
);

FfiResult_bool fatoora_invoice_builder_set_buyer(
    FfiInvoiceBuilder* builder,
    const char* name,
    const char* country_code,
    const char* city,
    const char* street,
    const char* additional_street,
    const char* building_number,
    const char* additional_number,
    const char* postal_code,
    const char* subdivision,
    const char* district,
    const char* vat_id,
    const char* other_id_value,
    const char* other_id_scheme
);

FfiResult_bool fatoora_invoice_builder_set_note(
    FfiInvoiceBuilder* builder,
    const char* language,
    const char* text
);

FfiResult_bool fatoora_invoice_builder_set_allowance(
    FfiInvoiceBuilder* builder,
    const char* reason,
    double amount
);

FfiResult_bool fatoora_invoice_builder_set_flags(
    FfiInvoiceBuilder* builder,
    unsigned char flags
);

FfiResult_FfiFinalizedInvoice fatoora_invoice_builder_build(FfiInvoiceBuilder* builder);
void fatoora_invoice_builder_free(FfiInvoiceBuilder* builder);

FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml(const char* xml);
FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml_file(const char* path);
FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml(const char* xml);
FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml_file(const char* path);

FfiResult_u64 fatoora_invoice_line_item_count(FfiFinalizedInvoice* invoice);
FfiResult_u64 fatoora_signed_invoice_line_item_count(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_invoice_line_item_description(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_FfiString fatoora_invoice_line_item_unit_code(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_f64 fatoora_invoice_line_item_quantity(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_f64 fatoora_invoice_line_item_unit_price(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_f64 fatoora_invoice_line_item_total_amount(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_f64 fatoora_invoice_line_item_vat_rate(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_f64 fatoora_invoice_line_item_vat_amount(FfiFinalizedInvoice* invoice, unsigned long long index);
FfiResult_u8 fatoora_invoice_line_item_vat_category(FfiFinalizedInvoice* invoice, unsigned long long index);

FfiResult_FfiString fatoora_signed_invoice_line_item_description(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_FfiString fatoora_signed_invoice_line_item_unit_code(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_f64 fatoora_signed_invoice_line_item_quantity(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_f64 fatoora_signed_invoice_line_item_unit_price(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_f64 fatoora_signed_invoice_line_item_total_amount(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_f64 fatoora_signed_invoice_line_item_vat_rate(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_f64 fatoora_signed_invoice_line_item_vat_amount(FfiSignedInvoice* signed, unsigned long long index);
FfiResult_u8 fatoora_signed_invoice_line_item_vat_category(FfiSignedInvoice* signed, unsigned long long index);

FfiResult_f64 fatoora_invoice_totals_tax_inclusive(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_totals_tax_amount(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_totals_line_extension(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_totals_allowance_total(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_totals_charge_total(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_totals_taxable_amount(FfiFinalizedInvoice* invoice);

FfiResult_f64 fatoora_signed_invoice_totals_tax_inclusive(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_totals_tax_amount(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_totals_line_extension(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_totals_allowance_total(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_totals_charge_total(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_totals_taxable_amount(FfiSignedInvoice* signed);

FfiResult_u8 fatoora_invoice_flags(FfiFinalizedInvoice* invoice);
FfiResult_u8 fatoora_signed_invoice_flags(FfiSignedInvoice* signed);

FfiResult_FfiString fatoora_invoice_id(FfiFinalizedInvoice* invoice);
FfiResult_FfiString fatoora_invoice_uuid(FfiFinalizedInvoice* invoice);
FfiResult_FfiString fatoora_invoice_issue_datetime(FfiFinalizedInvoice* invoice);
FfiResult_FfiString fatoora_invoice_currency(FfiFinalizedInvoice* invoice);
FfiResult_FfiString fatoora_invoice_previous_hash(FfiFinalizedInvoice* invoice);
FfiResult_u64 fatoora_invoice_counter(FfiFinalizedInvoice* invoice);
FfiResult_FfiString fatoora_invoice_payment_means_code(FfiFinalizedInvoice* invoice);
FfiResult_FfiVatCategory fatoora_invoice_vat_category(FfiFinalizedInvoice* invoice);
FfiResult_FfiString fatoora_invoice_allowance_reason(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_level_charge(FfiFinalizedInvoice* invoice);
FfiResult_f64 fatoora_invoice_level_discount(FfiFinalizedInvoice* invoice);

FfiResult_FfiString fatoora_invoice_to_xml(FfiFinalizedInvoice* invoice);
FfiResult_FfiString fatoora_invoice_hash_base64(FfiFinalizedInvoice* invoice);
void fatoora_invoice_free(FfiFinalizedInvoice* invoice);

FfiResult_FfiParty fatoora_invoice_seller(FfiFinalizedInvoice* invoice);
FfiResult_FfiParty fatoora_invoice_buyer(FfiFinalizedInvoice* invoice);
FfiResult_FfiInvoiceNote fatoora_invoice_note(FfiFinalizedInvoice* invoice);
FfiResult_FfiInvoiceTypeKind fatoora_invoice_type_kind(FfiFinalizedInvoice* invoice);
FfiResult_FfiInvoiceSubType fatoora_invoice_sub_type(FfiFinalizedInvoice* invoice);
FfiResult_FfiOriginalInvoiceRef fatoora_invoice_original_ref(FfiFinalizedInvoice* invoice);
FfiResult_FfiString fatoora_invoice_original_reason(FfiFinalizedInvoice* invoice);

FfiResult_FfiSigner fatoora_signer_from_pem(const char* cert_pem, const char* key_pem);
FfiResult_FfiSigner fatoora_signer_from_der(const unsigned char* cert_der, uintptr_t cert_len, const unsigned char* key_der, uintptr_t key_len);
void fatoora_signer_free(FfiSigner* signer);
FfiResult_FfiSignedInvoice fatoora_invoice_sign(FfiFinalizedInvoice* invoice, FfiSigner* signer);

FfiResult_FfiString fatoora_signed_invoice_xml(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_xml_base64(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_qr(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_uuid(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_hash(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_hash_base64(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_signature(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_public_key(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_zatca_key_signature(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_cert_hash(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_signed_props_hash(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_signing_time(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_id(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_issue_datetime(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_currency(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_previous_hash(FfiSignedInvoice* signed);
FfiResult_u64 fatoora_signed_invoice_counter(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_payment_means_code(FfiSignedInvoice* signed);
FfiResult_FfiVatCategory fatoora_signed_invoice_vat_category(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_allowance_reason(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_level_charge(FfiSignedInvoice* signed);
FfiResult_f64 fatoora_signed_invoice_level_discount(FfiSignedInvoice* signed);
FfiResult_FfiParty fatoora_signed_invoice_seller(FfiSignedInvoice* signed);
FfiResult_FfiParty fatoora_signed_invoice_buyer(FfiSignedInvoice* signed);
FfiResult_FfiInvoiceNote fatoora_signed_invoice_note(FfiSignedInvoice* signed);
FfiResult_FfiInvoiceTypeKind fatoora_signed_invoice_type_kind(FfiSignedInvoice* signed);
FfiResult_FfiInvoiceSubType fatoora_signed_invoice_sub_type(FfiSignedInvoice* signed);
FfiResult_FfiOriginalInvoiceRef fatoora_signed_invoice_original_ref(FfiSignedInvoice* signed);
FfiResult_FfiString fatoora_signed_invoice_original_reason(FfiSignedInvoice* signed);
void fatoora_signed_invoice_free(FfiSignedInvoice* signed);

void fatoora_party_free(FfiParty* party);
FfiResult_FfiString fatoora_party_name(FfiParty* party);
FfiResult_FfiAddress fatoora_party_address(FfiParty* party);
FfiResult_FfiVatId fatoora_party_vat_id(FfiParty* party);
FfiResult_FfiOtherId fatoora_party_other_id(FfiParty* party);

void fatoora_address_free(FfiAddress* address);
FfiResult_FfiString fatoora_address_country_code(FfiAddress* address);
FfiResult_FfiString fatoora_address_city(FfiAddress* address);
FfiResult_FfiString fatoora_address_street(FfiAddress* address);
FfiResult_FfiString fatoora_address_additional_street(FfiAddress* address);
FfiResult_FfiString fatoora_address_building_number(FfiAddress* address);
FfiResult_FfiString fatoora_address_additional_number(FfiAddress* address);
FfiResult_FfiString fatoora_address_postal_code(FfiAddress* address);
FfiResult_FfiString fatoora_address_subdivision(FfiAddress* address);
FfiResult_FfiString fatoora_address_district(FfiAddress* address);

void fatoora_vat_id_free(FfiVatId* vat);
FfiResult_FfiString fatoora_vat_id_value(FfiVatId* vat);

void fatoora_other_id_free(FfiOtherId* other);
FfiResult_FfiString fatoora_other_id_value(FfiOtherId* other);
FfiResult_FfiString fatoora_other_id_scheme(FfiOtherId* other);

void fatoora_invoice_note_free(FfiInvoiceNote* note);
FfiResult_FfiString fatoora_invoice_note_language(FfiInvoiceNote* note);
FfiResult_FfiString fatoora_invoice_note_text(FfiInvoiceNote* note);

void fatoora_original_invoice_ref_free(FfiOriginalInvoiceRef* reference);
FfiResult_FfiString fatoora_original_invoice_ref_id(FfiOriginalInvoiceRef* reference);
FfiResult_FfiString fatoora_original_invoice_ref_uuid(FfiOriginalInvoiceRef* reference);
FfiResult_FfiString fatoora_original_invoice_ref_issue_date(FfiOriginalInvoiceRef* reference);
"""


class FfiLibrary:
    def __init__(self, path: str | None = None) -> None:
        if path is None:
            path = self._default_library_path()
        self.ffi = FFI()
        self.ffi.cdef(_load_cdef())
        self.lib = self.ffi.dlopen(path)

    @staticmethod
    def _default_library_path() -> str:
        env_path = os.environ.get("FATOORA_FFI_PATH")
        if env_path:
            return env_path

        base = Path(__file__).resolve().parent
        names = ("libfatoora_ffi.so", "libfatoora_ffi.dylib", "fatoora_ffi.dll")
        for name in names:
            candidate = base / name
            if candidate.exists():
                return str(candidate)

        repo_root = base.parents[2]
        for name in names:
            for build in ("release", "debug"):
                candidate = repo_root / "target" / build / name
                if candidate.exists():
                    return str(candidate)

        raise FileNotFoundError(
            "fatoora-ffi shared library not found. Build with "
            "`cargo build -p fatoora-ffi --release` or set FATOORA_FFI_PATH."
        )


def _load_cdef() -> str:
    header = _find_header()
    if header is None:
        return _CDEF
    try:
        header_text = Path(header).read_text(encoding="utf-8")
        if "FfiValidationResponse" not in header_text or "fatoora_invoice_seller" not in header_text:
            return _CDEF
        return _CDEF_PREAMBLE + _cdef_from_header(header)
    except OSError:
        return _CDEF


def _find_header() -> str | None:
    env_path = os.environ.get("FATOORA_FFI_HEADER")
    if env_path:
        return env_path

    base = Path(__file__).resolve().parent
    candidate = base / "fatoora_ffi.h"
    if candidate.exists():
        return str(candidate)

    repo_root = base.parents[2]
    candidate = repo_root / "fatoora-ffi" / "include" / "fatoora_ffi.h"
    if candidate.exists():
        return str(candidate)

    return None


def _cdef_from_header(path: str) -> str:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    in_extern = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("extern \"C\""):
            in_extern = True
            continue
        if in_extern and stripped.startswith("}"):
            in_extern = False
            continue
        if stripped.startswith("namespace "):
            continue
        if stripped.startswith("} // namespace"):
            continue
        out.append(line)
    return "\n".join(out)
