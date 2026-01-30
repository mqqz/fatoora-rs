#ifndef FATOORA_FFI_H
#define FATOORA_FFI_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

enum FfiEnvironment {
  FfiEnvironment_NonProduction = 0,
  FfiEnvironment_Simulation = 1,
  FfiEnvironment_Production = 2,
};
typedef int32_t FfiEnvironment;

enum FfiInvoiceTypeKind {
  FfiInvoiceTypeKind_Tax = 0,
  FfiInvoiceTypeKind_Prepayment = 1,
  FfiInvoiceTypeKind_CreditNote = 2,
  FfiInvoiceTypeKind_DebitNote = 3,
};
typedef int32_t FfiInvoiceTypeKind;

enum FfiInvoiceSubType {
  FfiInvoiceSubType_Standard = 0,
  FfiInvoiceSubType_Simplified = 1,
};
typedef int32_t FfiInvoiceSubType;

enum FfiVatCategory {
  FfiVatCategory_Exempt = 0,
  FfiVatCategory_Standard = 1,
  FfiVatCategory_Zero = 2,
  FfiVatCategory_OutOfScope = 3,
};
typedef int32_t FfiVatCategory;

enum FfiInvoiceFlag {
  FfiInvoiceFlag_ThirdParty = 1,
  FfiInvoiceFlag_Nominal = 2,
  FfiInvoiceFlag_Export = 4,
  FfiInvoiceFlag_Summary = 8,
  FfiInvoiceFlag_SelfBilled = 16,
};
typedef uint8_t FfiInvoiceFlag;

typedef struct FfiString {
  char *ptr;
} FfiString;

typedef struct FfiBytes {
  uint8_t *ptr;
  uintptr_t len;
} FfiBytes;

typedef struct FfiBytesList {
  struct FfiBytes *ptr;
  uintptr_t len;
} FfiBytesList;

typedef struct FfiConfig {
  void *ptr;
} FfiConfig;

typedef struct FfiError {
  int32_t code;
  char *message;
} FfiError;

typedef struct FfiResult_FfiEnvironment {
  bool ok;
  FfiEnvironment value;
  struct FfiError *error;
} FfiResult_FfiEnvironment;

typedef struct FfiCsrProperties {
  void *ptr;
} FfiCsrProperties;

typedef struct FfiResult_FfiCsrProperties {
  bool ok;
  struct FfiCsrProperties value;
  struct FfiError *error;
} FfiResult_FfiCsrProperties;

typedef struct FfiSigningKey {
  void *ptr;
} FfiSigningKey;

typedef struct FfiResult_FfiSigningKey {
  bool ok;
  struct FfiSigningKey value;
  struct FfiError *error;
} FfiResult_FfiSigningKey;

typedef struct FfiResult_FfiString {
  bool ok;
  struct FfiString value;
  struct FfiError *error;
} FfiResult_FfiString;

typedef struct FfiResult_FfiBytes {
  bool ok;
  struct FfiBytes value;
  struct FfiError *error;
} FfiResult_FfiBytes;

typedef struct FfiCsr {
  void *ptr;
} FfiCsr;

typedef struct FfiResult_FfiCsr {
  bool ok;
  struct FfiCsr value;
  struct FfiError *error;
} FfiResult_FfiCsr;

typedef struct FfiResult_FfiBytesList {
  bool ok;
  struct FfiBytesList value;
  struct FfiError *error;
} FfiResult_FfiBytesList;

typedef struct FfiZatcaClient {
  void *ptr;
} FfiZatcaClient;

typedef struct FfiResult_FfiZatcaClient {
  bool ok;
  struct FfiZatcaClient value;
  struct FfiError *error;
} FfiResult_FfiZatcaClient;

typedef struct FfiCsidCompliance {
  void *ptr;
} FfiCsidCompliance;

typedef struct FfiResult_FfiCsidCompliance {
  bool ok;
  struct FfiCsidCompliance value;
  struct FfiError *error;
} FfiResult_FfiCsidCompliance;

typedef struct FfiCsidProduction {
  void *ptr;
} FfiCsidProduction;

typedef struct FfiResult_FfiCsidProduction {
  bool ok;
  struct FfiCsidProduction value;
  struct FfiError *error;
} FfiResult_FfiCsidProduction;

typedef struct FfiValidationResponse {
  void *ptr;
} FfiValidationResponse;

typedef struct FfiResult_FfiValidationResponse {
  bool ok;
  struct FfiValidationResponse value;
  struct FfiError *error;
} FfiResult_FfiValidationResponse;

typedef struct FfiSignedInvoice {
  void *ptr;
} FfiSignedInvoice;

typedef struct FfiValidationResults {
  void *ptr;
} FfiValidationResults;

typedef struct FfiResult_FfiValidationResults {
  bool ok;
  struct FfiValidationResults value;
  struct FfiError *error;
} FfiResult_FfiValidationResults;

typedef struct FfiResult_u64 {
  bool ok;
  uint64_t value;
  struct FfiError *error;
} FfiResult_u64;

typedef struct FfiValidationMessage {
  void *ptr;
} FfiValidationMessage;

typedef struct FfiResult_FfiValidationMessage {
  bool ok;
  struct FfiValidationMessage value;
  struct FfiError *error;
} FfiResult_FfiValidationMessage;

typedef struct FfiResult_bool {
  bool ok;
  bool value;
  struct FfiError *error;
} FfiResult_bool;

typedef struct FfiInvoiceBuilder {
  void *ptr;
} FfiInvoiceBuilder;

typedef struct FfiResult_FfiInvoiceBuilder {
  bool ok;
  struct FfiInvoiceBuilder value;
  struct FfiError *error;
} FfiResult_FfiInvoiceBuilder;

typedef struct FfiFinalizedInvoice {
  void *ptr;
} FfiFinalizedInvoice;

typedef struct FfiResult_FfiFinalizedInvoice {
  bool ok;
  struct FfiFinalizedInvoice value;
  struct FfiError *error;
} FfiResult_FfiFinalizedInvoice;

typedef struct FfiResult_FfiSignedInvoice {
  bool ok;
  struct FfiSignedInvoice value;
  struct FfiError *error;
} FfiResult_FfiSignedInvoice;

typedef struct FfiResult_f64 {
  bool ok;
  double value;
  struct FfiError *error;
} FfiResult_f64;

typedef struct FfiResult_u8 {
  bool ok;
  uint8_t value;
  struct FfiError *error;
} FfiResult_u8;

typedef struct FfiSigner {
  void *ptr;
} FfiSigner;

typedef struct FfiResult_FfiSigner {
  bool ok;
  struct FfiSigner value;
  struct FfiError *error;
} FfiResult_FfiSigner;

typedef struct FfiParty {
  void *ptr;
} FfiParty;

typedef struct FfiResult_FfiParty {
  bool ok;
  struct FfiParty value;
  struct FfiError *error;
} FfiResult_FfiParty;

typedef struct FfiInvoiceNote {
  void *ptr;
} FfiInvoiceNote;

typedef struct FfiResult_FfiInvoiceNote {
  bool ok;
  struct FfiInvoiceNote value;
  struct FfiError *error;
} FfiResult_FfiInvoiceNote;

typedef struct FfiResult_FfiVatCategory {
  bool ok;
  FfiVatCategory value;
  struct FfiError *error;
} FfiResult_FfiVatCategory;

typedef struct FfiResult_FfiInvoiceTypeKind {
  bool ok;
  FfiInvoiceTypeKind value;
  struct FfiError *error;
} FfiResult_FfiInvoiceTypeKind;

typedef struct FfiResult_FfiInvoiceSubType {
  bool ok;
  FfiInvoiceSubType value;
  struct FfiError *error;
} FfiResult_FfiInvoiceSubType;

typedef struct FfiOriginalInvoiceRef {
  void *ptr;
} FfiOriginalInvoiceRef;

typedef struct FfiResult_FfiOriginalInvoiceRef {
  bool ok;
  struct FfiOriginalInvoiceRef value;
  struct FfiError *error;
} FfiResult_FfiOriginalInvoiceRef;

typedef struct FfiAddress {
  void *ptr;
} FfiAddress;

typedef struct FfiResult_FfiAddress {
  bool ok;
  struct FfiAddress value;
  struct FfiError *error;
} FfiResult_FfiAddress;

typedef struct FfiVatId {
  void *ptr;
} FfiVatId;

typedef struct FfiResult_FfiVatId {
  bool ok;
  struct FfiVatId value;
  struct FfiError *error;
} FfiResult_FfiVatId;

typedef struct FfiOtherId {
  void *ptr;
} FfiOtherId;

typedef struct FfiResult_FfiOtherId {
  bool ok;
  struct FfiOtherId value;
  struct FfiError *error;
} FfiResult_FfiOtherId;

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_string_free(struct FfiString value);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_bytes_free(struct FfiBytes bytes);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_bytes_list_free(struct FfiBytesList list);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiConfig *fatoora_config_new(FfiEnvironment env);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiEnvironment fatoora_config_env(struct FfiConfig *config);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_config_free(struct FfiConfig *config);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsrProperties fatoora_csr_properties_from_str(const char *properties);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsrProperties fatoora_csr_properties_parse(const char *properties);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsrProperties fatoora_csr_properties_parse_file(const char *path);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_csr_properties_free(struct FfiCsrProperties *props);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiSigningKey fatoora_signing_key_from_pem(const char *pem);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiSigningKey fatoora_signing_key_from_der(const uint8_t *der, uintptr_t len);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiSigningKey fatoora_signing_key_generate(void);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signing_key_to_pem(struct FfiSigningKey *key);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiBytes fatoora_signing_key_to_der(struct FfiSigningKey *key);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_signing_key_free(struct FfiSigningKey *key);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsr fatoora_csr_build(struct FfiCsrProperties *props,
                                          struct FfiSigningKey *key,
                                          FfiEnvironment env);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsr fatoora_csr_from_der(const uint8_t *der, uintptr_t len);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csr_to_base64(struct FfiCsr *csr);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csr_to_pem_base64(struct FfiCsr *csr);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiBytes fatoora_csr_to_der(struct FfiCsr *csr);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csr_to_pem(struct FfiCsr *csr);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csr_subject_string(struct FfiCsr *csr);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiBytesList fatoora_csr_extension_values_der(struct FfiCsr *csr);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_csr_free(struct FfiCsr *csr);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiZatcaClient fatoora_zatca_client_new(struct FfiConfig *config);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_zatca_client_free(struct FfiZatcaClient *client);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsidCompliance fatoora_csid_compliance_new(FfiEnvironment env,
                                                               const char *request_id,
                                                               const char *token,
                                                               const char *secret);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsidProduction fatoora_csid_production_new(FfiEnvironment env,
                                                               const char *request_id,
                                                               const char *token,
                                                               const char *secret);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csid_compliance_request_id(struct FfiCsidCompliance *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiEnvironment fatoora_csid_compliance_env(struct FfiCsidCompliance *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csid_production_request_id(struct FfiCsidProduction *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiEnvironment fatoora_csid_production_env(struct FfiCsidProduction *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csid_compliance_token(struct FfiCsidCompliance *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csid_compliance_secret(struct FfiCsidCompliance *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csid_production_token(struct FfiCsidProduction *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csid_production_secret(struct FfiCsidProduction *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_csid_compliance_free(struct FfiCsidCompliance *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_csid_production_free(struct FfiCsidProduction *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsidCompliance fatoora_zatca_post_csr_for_ccsid(struct FfiZatcaClient *client,
                                                                    struct FfiCsr *csr,
                                                                    const char *otp);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsidProduction fatoora_zatca_post_ccsid_for_pcsid(struct FfiZatcaClient *client,
                                                                      struct FfiCsidCompliance *ccsid);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsidProduction fatoora_zatca_renew_csid(struct FfiZatcaClient *client,
                                                            struct FfiCsidProduction *pcsid,
                                                            struct FfiCsr *csr,
                                                            const char *otp,
                                                            const char *accept_language);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiValidationResponse fatoora_zatca_check_compliance(struct FfiZatcaClient *client,
                                                                      struct FfiSignedInvoice *invoice,
                                                                      struct FfiCsidCompliance *ccsid);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiValidationResponse fatoora_zatca_report_simplified_invoice(struct FfiZatcaClient *client,
                                                                               struct FfiSignedInvoice *invoice,
                                                                               struct FfiCsidProduction *pcsid,
                                                                               bool clearance_status,
                                                                               const char *accept_language);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiValidationResponse fatoora_zatca_clear_standard_invoice(struct FfiZatcaClient *client,
                                                                            struct FfiSignedInvoice *invoice,
                                                                            struct FfiCsidProduction *pcsid,
                                                                            bool clearance_status,
                                                                            const char *accept_language);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_validation_response_free(struct FfiValidationResponse *response);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_validation_response_reporting_status(struct FfiValidationResponse *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_validation_response_clearance_status(struct FfiValidationResponse *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_validation_response_qr_seller_status(struct FfiValidationResponse *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_validation_response_qr_buyer_status(struct FfiValidationResponse *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiValidationResults fatoora_validation_response_results(struct FfiValidationResponse *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_validation_results_free(struct FfiValidationResults *results);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_validation_results_status(struct FfiValidationResults *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u64 fatoora_validation_results_info_len(struct FfiValidationResults *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u64 fatoora_validation_results_warning_len(struct FfiValidationResults *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u64 fatoora_validation_results_error_len(struct FfiValidationResults *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiValidationMessage fatoora_validation_results_info_message(struct FfiValidationResults *results,
                                                                              uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiValidationMessage fatoora_validation_results_warning_message(struct FfiValidationResults *results,
                                                                                 uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiValidationMessage fatoora_validation_results_error_message(struct FfiValidationResults *results,
                                                                               uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_validation_message_free(struct FfiValidationMessage *message);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_validation_message_type(struct FfiValidationMessage *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_validation_message_code(struct FfiValidationMessage *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_validation_message_category(struct FfiValidationMessage *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_validation_message_text(struct FfiValidationMessage *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_validation_message_status(struct FfiValidationMessage *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_validate_xml_str(struct FfiConfig *config, const char *xml);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiInvoiceBuilder fatoora_invoice_builder_new(FfiInvoiceTypeKind invoice_type_kind,
                                                               FfiInvoiceSubType invoice_sub_type,
                                                               const char *original_invoice_id,
                                                               const char *original_invoice_uuid,
                                                               const char *original_invoice_issue_date,
                                                               const char *original_invoice_reason);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_id(struct FfiInvoiceBuilder *builder,
                                                     const char *id);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_uuid(struct FfiInvoiceBuilder *builder,
                                                       const char *uuid);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_issue_datetime(struct FfiInvoiceBuilder *builder,
                                                                 const char *issue_timestamp);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_currency(struct FfiInvoiceBuilder *builder,
                                                           const char *currency_code);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_previous_hash(struct FfiInvoiceBuilder *builder,
                                                                const char *hash);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_invoice_counter(struct FfiInvoiceBuilder *builder,
                                                                  uint64_t counter);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_payment_means_code(struct FfiInvoiceBuilder *builder,
                                                                     const char *payment_means_code);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_vat_category(struct FfiInvoiceBuilder *builder,
                                                               FfiVatCategory vat_category);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_seller(struct FfiInvoiceBuilder *builder,
                                                         const char *name,
                                                         const char *country_code,
                                                         const char *city,
                                                         const char *street,
                                                         const char *additional_street,
                                                         const char *building_number,
                                                         const char *additional_number,
                                                         const char *postal_code,
                                                         const char *subdivision,
                                                         const char *district,
                                                         const char *vat_id,
                                                         const char *other_id_value,
                                                         const char *other_id_scheme);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_flags(struct FfiInvoiceBuilder *builder,
                                                        uint8_t flags);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_add_line_item(struct FfiInvoiceBuilder *builder,
                                                            const char *description,
                                                            double quantity,
                                                            const char *unit_code,
                                                            double unit_price,
                                                            double vat_rate,
                                                            FfiVatCategory vat_category);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_buyer(struct FfiInvoiceBuilder *builder,
                                                        const char *name,
                                                        const char *country_code,
                                                        const char *city,
                                                        const char *street,
                                                        const char *additional_street,
                                                        const char *building_number,
                                                        const char *additional_number,
                                                        const char *postal_code,
                                                        const char *subdivision,
                                                        const char *district,
                                                        const char *vat_id,
                                                        const char *other_id_value,
                                                        const char *other_id_scheme);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_note(struct FfiInvoiceBuilder *builder,
                                                       const char *language,
                                                       const char *text);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_set_allowance(struct FfiInvoiceBuilder *builder,
                                                            const char *reason,
                                                            double amount);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_invoice_builder_free(struct FfiInvoiceBuilder *builder);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiFinalizedInvoice fatoora_invoice_builder_build(struct FfiInvoiceBuilder *builder);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml(const char *xml);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiFinalizedInvoice fatoora_parse_finalized_invoice_xml_file(const char *path);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml(const char *xml);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml_file(const char *path);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u64 fatoora_invoice_line_item_count(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u64 fatoora_signed_invoice_line_item_count(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_line_item_description(struct FfiFinalizedInvoice *invoice,
                                                                 uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_line_item_unit_code(struct FfiFinalizedInvoice *invoice,
                                                               uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_line_item_quantity(struct FfiFinalizedInvoice *invoice,
                                                        uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_line_item_unit_price(struct FfiFinalizedInvoice *invoice,
                                                          uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_line_item_total_amount(struct FfiFinalizedInvoice *invoice,
                                                            uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_line_item_vat_rate(struct FfiFinalizedInvoice *invoice,
                                                        uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_line_item_vat_amount(struct FfiFinalizedInvoice *invoice,
                                                          uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u8 fatoora_invoice_line_item_vat_category(struct FfiFinalizedInvoice *invoice,
                                                           uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_line_item_description(struct FfiSignedInvoice *signed_,
                                                                        uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_line_item_unit_code(struct FfiSignedInvoice *signed_,
                                                                      uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_line_item_quantity(struct FfiSignedInvoice *signed_,
                                                               uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_line_item_unit_price(struct FfiSignedInvoice *signed_,
                                                                 uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_line_item_total_amount(struct FfiSignedInvoice *signed_,
                                                                   uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_line_item_vat_rate(struct FfiSignedInvoice *signed_,
                                                               uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_line_item_vat_amount(struct FfiSignedInvoice *signed_,
                                                                 uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u8 fatoora_signed_invoice_line_item_vat_category(struct FfiSignedInvoice *signed_,
                                                                  uint64_t index);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_tax_inclusive(struct FfiFinalizedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_tax_amount(struct FfiFinalizedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_line_extension(struct FfiFinalizedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_allowance_total(struct FfiFinalizedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_charge_total(struct FfiFinalizedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_taxable_amount(struct FfiFinalizedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_tax_inclusive(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_tax_amount(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_line_extension(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_allowance_total(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_charge_total(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_taxable_amount(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u8 fatoora_invoice_flags(struct FfiFinalizedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u8 fatoora_signed_invoice_flags(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_to_xml(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_hash_base64(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_invoice_free(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiSigner fatoora_signer_from_pem(const char *cert_pem, const char *key_pem);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiSigner fatoora_signer_from_der(const uint8_t *cert_der,
                                                   uintptr_t cert_len,
                                                   const uint8_t *key_der,
                                                   uintptr_t key_len);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_signer_free(struct FfiSigner *signer);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiSignedInvoice fatoora_invoice_sign(struct FfiFinalizedInvoice *invoice,
                                                       struct FfiSigner *signer);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_xml(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_qr(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_uuid(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_hash(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_hash_base64(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_signature(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_public_key(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_zatca_key_signature(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_cert_hash(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_signed_props_hash(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_signing_time(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiParty fatoora_invoice_seller(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiParty fatoora_invoice_buyer(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiInvoiceNote fatoora_invoice_note(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_id(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_uuid(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_issue_datetime(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_currency(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_previous_hash(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u64 fatoora_invoice_counter(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_payment_means_code(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiVatCategory fatoora_invoice_vat_category(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_allowance_reason(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_level_charge(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_level_discount(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiInvoiceTypeKind fatoora_invoice_type_kind(struct FfiFinalizedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiInvoiceSubType fatoora_invoice_sub_type(struct FfiFinalizedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiOriginalInvoiceRef fatoora_invoice_original_ref(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_original_reason(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiParty fatoora_signed_invoice_seller(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiParty fatoora_signed_invoice_buyer(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiInvoiceNote fatoora_signed_invoice_note(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_id(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_issue_datetime(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_currency(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_previous_hash(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u64 fatoora_signed_invoice_counter(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_payment_means_code(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiVatCategory fatoora_signed_invoice_vat_category(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_allowance_reason(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_level_charge(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_level_discount(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiInvoiceTypeKind fatoora_signed_invoice_type_kind(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiInvoiceSubType fatoora_signed_invoice_sub_type(struct FfiSignedInvoice *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiOriginalInvoiceRef fatoora_signed_invoice_original_ref(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_original_reason(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_party_free(struct FfiParty *party);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_party_name(struct FfiParty *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiAddress fatoora_party_address(struct FfiParty *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiVatId fatoora_party_vat_id(struct FfiParty *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiOtherId fatoora_party_other_id(struct FfiParty *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_address_free(struct FfiAddress *address);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_address_country_code(struct FfiAddress *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_address_city(struct FfiAddress *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_address_street(struct FfiAddress *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_address_additional_street(struct FfiAddress *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_address_building_number(struct FfiAddress *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_address_additional_number(struct FfiAddress *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_address_postal_code(struct FfiAddress *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_address_subdivision(struct FfiAddress *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_address_district(struct FfiAddress *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_vat_id_free(struct FfiVatId *vat);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_vat_id_value(struct FfiVatId *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_other_id_free(struct FfiOtherId *other);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_other_id_value(struct FfiOtherId *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_other_id_scheme(struct FfiOtherId *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_invoice_note_free(struct FfiInvoiceNote *note);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_note_language(struct FfiInvoiceNote *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_note_text(struct FfiInvoiceNote *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_original_invoice_ref_free(struct FfiOriginalInvoiceRef *reference);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_original_invoice_ref_id(struct FfiOriginalInvoiceRef *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_original_invoice_ref_uuid(struct FfiOriginalInvoiceRef *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_original_invoice_ref_issue_date(struct FfiOriginalInvoiceRef *handle);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_signed_invoice_xml_base64(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_signed_invoice_free(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_error_free(struct FfiError *error);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
int32_t fatoora_error_code(struct FfiError *error);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiString fatoora_error_message(struct FfiError *error);

#endif  /* FATOORA_FFI_H */
