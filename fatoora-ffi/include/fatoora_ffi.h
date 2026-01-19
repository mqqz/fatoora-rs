#ifndef FATOORA_FFI_H
#define FATOORA_FFI_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum FfiEnvironment {
  FfiEnvironment_NonProduction,
  FfiEnvironment_Simulation,
  FfiEnvironment_Production,
} FfiEnvironment;

typedef enum FfiInvoiceTypeKind {
  FfiInvoiceTypeKind_Tax,
  FfiInvoiceTypeKind_Prepayment,
  FfiInvoiceTypeKind_CreditNote,
  FfiInvoiceTypeKind_DebitNote,
} FfiInvoiceTypeKind;

typedef enum FfiInvoiceSubType {
  FfiInvoiceSubType_Standard,
  FfiInvoiceSubType_Simplified,
} FfiInvoiceSubType;

typedef enum FfiVatCategory {
  FfiVatCategory_Exempt,
  FfiVatCategory_Standard,
  FfiVatCategory_Zero,
  FfiVatCategory_OutOfScope,
} FfiVatCategory;

typedef struct FfiString {
  char *ptr;
} FfiString;

typedef struct FfiConfig {
  void *ptr;
} FfiConfig;

typedef struct FfiCsrProperties {
  void *ptr;
} FfiCsrProperties;

typedef struct FfiResult_FfiCsrProperties {
  bool ok;
  struct FfiCsrProperties value;
  char *error;
} FfiResult_FfiCsrProperties;

typedef struct FfiSigningKey {
  void *ptr;
} FfiSigningKey;

typedef struct FfiResult_FfiSigningKey {
  bool ok;
  struct FfiSigningKey value;
  char *error;
} FfiResult_FfiSigningKey;

typedef struct FfiResult_FfiString {
  bool ok;
  struct FfiString value;
  char *error;
} FfiResult_FfiString;

typedef struct FfiCsr {
  void *ptr;
} FfiCsr;

typedef struct FfiCsrBundle {
  struct FfiCsr csr;
  struct FfiSigningKey key;
} FfiCsrBundle;

typedef struct FfiResult_FfiCsrBundle {
  bool ok;
  struct FfiCsrBundle value;
  char *error;
} FfiResult_FfiCsrBundle;

typedef struct FfiResult_FfiCsr {
  bool ok;
  struct FfiCsr value;
  char *error;
} FfiResult_FfiCsr;

typedef struct FfiZatcaClient {
  void *ptr;
} FfiZatcaClient;

typedef struct FfiResult_FfiZatcaClient {
  bool ok;
  struct FfiZatcaClient value;
  char *error;
} FfiResult_FfiZatcaClient;

typedef struct FfiCsidCompliance {
  void *ptr;
} FfiCsidCompliance;

typedef struct FfiResult_FfiCsidCompliance {
  bool ok;
  struct FfiCsidCompliance value;
  char *error;
} FfiResult_FfiCsidCompliance;

typedef struct FfiCsidProduction {
  void *ptr;
} FfiCsidProduction;

typedef struct FfiResult_FfiCsidProduction {
  bool ok;
  struct FfiCsidProduction value;
  char *error;
} FfiResult_FfiCsidProduction;

typedef struct FfiResult_u64 {
  bool ok;
  uint64_t value;
  char *error;
} FfiResult_u64;

typedef struct FfiSignedInvoice {
  void *ptr;
} FfiSignedInvoice;

typedef struct FfiResult_bool {
  bool ok;
  bool value;
  char *error;
} FfiResult_bool;

typedef struct FfiInvoiceBuilder {
  void *ptr;
} FfiInvoiceBuilder;

typedef struct FfiResult_FfiInvoiceBuilder {
  bool ok;
  struct FfiInvoiceBuilder value;
  char *error;
} FfiResult_FfiInvoiceBuilder;

typedef struct FfiFinalizedInvoice {
  void *ptr;
} FfiFinalizedInvoice;

typedef struct FfiResult_FfiFinalizedInvoice {
  bool ok;
  struct FfiFinalizedInvoice value;
  char *error;
} FfiResult_FfiFinalizedInvoice;

typedef struct FfiResult_FfiSignedInvoice {
  bool ok;
  struct FfiSignedInvoice value;
  char *error;
} FfiResult_FfiSignedInvoice;

typedef struct FfiResult_f64 {
  bool ok;
  double value;
  char *error;
} FfiResult_f64;

typedef struct FfiResult_u8 {
  bool ok;
  uint8_t value;
  char *error;
} FfiResult_u8;

typedef struct FfiSigner {
  void *ptr;
} FfiSigner;

typedef struct FfiResult_FfiSigner {
  bool ok;
  struct FfiSigner value;
  char *error;
} FfiResult_FfiSigner;

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_string_free(struct FfiString value);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiConfig *fatoora_config_new(enum FfiEnvironment env);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiConfig *fatoora_config_with_xsd(enum FfiEnvironment env, const char *path);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_config_free(struct FfiConfig *config);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsrProperties fatoora_csr_properties_parse(const char *path);

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
struct FfiResult_FfiString fatoora_signing_key_to_pem(struct FfiSigningKey *key);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
void fatoora_signing_key_free(struct FfiSigningKey *key);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsrBundle fatoora_csr_build_with_rng(struct FfiCsrProperties *props,
                                                         enum FfiEnvironment env);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsr fatoora_csr_build(struct FfiCsrProperties *props,
                                          struct FfiSigningKey *key,
                                          enum FfiEnvironment env);

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
struct FfiResult_FfiCsidCompliance fatoora_csid_compliance_new(enum FfiEnvironment env,
                                                               bool has_request_id,
                                                               uint64_t request_id,
                                                               const char *token,
                                                               const char *secret);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiCsidProduction fatoora_csid_production_new(enum FfiEnvironment env,
                                                               bool has_request_id,
                                                               uint64_t request_id,
                                                               const char *token,
                                                               const char *secret);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u64 fatoora_csid_compliance_request_id(struct FfiCsidCompliance *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u64 fatoora_csid_production_request_id(struct FfiCsidProduction *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csid_compliance_token(struct FfiCsidCompliance *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csid_compliance_secret(struct FfiCsidCompliance *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csid_production_token(struct FfiCsidProduction *creds);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_csid_production_secret(struct FfiCsidProduction *creds);

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
struct FfiResult_FfiString fatoora_zatca_check_compliance(struct FfiZatcaClient *client,
                                                          struct FfiSignedInvoice *invoice,
                                                          struct FfiCsidCompliance *ccsid);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_zatca_report_simplified_invoice(struct FfiZatcaClient *client,
                                                                   struct FfiSignedInvoice *invoice,
                                                                   struct FfiCsidProduction *pcsid,
                                                                   bool clearance_status,
                                                                   const char *accept_language);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_zatca_clear_standard_invoice(struct FfiZatcaClient *client,
                                                                struct FfiSignedInvoice *invoice,
                                                                struct FfiCsidProduction *pcsid,
                                                                bool clearance_status,
                                                                const char *accept_language);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_validate_xml_str(struct FfiConfig *config, const char *xml);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_validate_xml_file(struct FfiConfig *config, const char *path);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiInvoiceBuilder fatoora_invoice_builder_new(enum FfiInvoiceTypeKind invoice_type_kind,
                                                               enum FfiInvoiceSubType invoice_sub_type,
                                                               const char *id,
                                                               const char *uuid,
                                                               int64_t issue_timestamp,
                                                               uint32_t issue_nanos,
                                                               const char *currency_code,
                                                               const char *previous_invoice_hash,
                                                               uint64_t invoice_counter,
                                                               const char *payment_means_code,
                                                               enum FfiVatCategory vat_category,
                                                               const char *seller_name,
                                                               const char *seller_country_code,
                                                               const char *seller_city,
                                                               const char *seller_street,
                                                               const char *seller_additional_street,
                                                               const char *seller_building_number,
                                                               const char *seller_additional_number,
                                                               const char *seller_postal_code,
                                                               const char *seller_subdivision,
                                                               const char *seller_district,
                                                               const char *seller_vat_id,
                                                               const char *seller_other_id,
                                                               const char *seller_other_id_scheme,
                                                               const char *original_invoice_id,
                                                               const char *original_invoice_uuid,
                                                               const char *original_invoice_issue_date,
                                                               const char *original_invoice_reason);

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
struct FfiResult_bool fatoora_invoice_builder_enable_flags(struct FfiInvoiceBuilder *builder,
                                                           uint8_t flags);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_bool fatoora_invoice_builder_disable_flags(struct FfiInvoiceBuilder *builder,
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
                                                            enum FfiVatCategory vat_category);

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
struct FfiResult_FfiSignedInvoice fatoora_parse_signed_invoice_xml(const char *xml);

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
struct FfiResult_f64 fatoora_invoice_totals_tax_inclusive(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_tax_amount(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_line_extension(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_allowance_total(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_charge_total(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_invoice_totals_taxable_amount(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_tax_inclusive(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_tax_amount(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_line_extension(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_allowance_total(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_charge_total(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_f64 fatoora_signed_invoice_totals_taxable_amount(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u8 fatoora_invoice_flags(struct FfiFinalizedInvoice *invoice);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_u8 fatoora_signed_invoice_flags(struct FfiSignedInvoice *signed_);

/**
 * # Safety
 * Caller must ensure all pointers are valid, properly aligned, and follow ownership requirements.
 */
struct FfiResult_FfiString fatoora_invoice_to_xml(struct FfiFinalizedInvoice *invoice);

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
void fatoora_error_free(char *error);

#endif  /* FATOORA_FFI_H */
