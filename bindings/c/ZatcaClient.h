#ifndef ZatcaClient_H
#define ZatcaClient_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Config.d.h"
#include "CsidCompliance.d.h"
#include "CsidProduction.d.h"
#include "Csr.d.h"
#include "SignedInvoice.d.h"
#include "ValidationResponse.d.h"

#include "ZatcaClient.d.h"






typedef struct fatoora_ZatcaClient_create_result {union {ZatcaClient* ok; BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_create_result;
fatoora_ZatcaClient_create_result fatoora_ZatcaClient_create(const Config* config);

typedef struct fatoora_ZatcaClient_post_csr_for_ccsid_result {union {CsidCompliance* ok; BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_post_csr_for_ccsid_result;
fatoora_ZatcaClient_post_csr_for_ccsid_result fatoora_ZatcaClient_post_csr_for_ccsid(const ZatcaClient* self, const Csr* csr, DiplomatStringView otp);

typedef struct fatoora_ZatcaClient_post_ccsid_for_pcsid_result {union {CsidProduction* ok; BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_post_ccsid_for_pcsid_result;
fatoora_ZatcaClient_post_ccsid_for_pcsid_result fatoora_ZatcaClient_post_ccsid_for_pcsid(const ZatcaClient* self, const CsidCompliance* credentials);

typedef struct fatoora_ZatcaClient_renew_csid_result {union {CsidProduction* ok; BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_renew_csid_result;
fatoora_ZatcaClient_renew_csid_result fatoora_ZatcaClient_renew_csid(const ZatcaClient* self, const CsidProduction* credentials, const Csr* csr, DiplomatStringView otp, OptionStringView accept_language);

typedef struct fatoora_ZatcaClient_check_invoice_compliance_result {union {ValidationResponse* ok; BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_check_invoice_compliance_result;
fatoora_ZatcaClient_check_invoice_compliance_result fatoora_ZatcaClient_check_invoice_compliance(const ZatcaClient* self, const SignedInvoice* invoice, const CsidCompliance* credentials);

typedef struct fatoora_ZatcaClient_report_simplified_invoice_result {union {ValidationResponse* ok; BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_report_simplified_invoice_result;
fatoora_ZatcaClient_report_simplified_invoice_result fatoora_ZatcaClient_report_simplified_invoice(const ZatcaClient* self, const SignedInvoice* invoice, const CsidProduction* credentials, bool clearance_status, OptionStringView accept_language);

typedef struct fatoora_ZatcaClient_clear_standard_invoice_result {union {ValidationResponse* ok; BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_clear_standard_invoice_result;
fatoora_ZatcaClient_clear_standard_invoice_result fatoora_ZatcaClient_clear_standard_invoice(const ZatcaClient* self, const SignedInvoice* invoice, const CsidProduction* credentials, bool clearance_status, OptionStringView accept_language);

void fatoora_ZatcaClient_destroy(ZatcaClient* self);





#endif // ZatcaClient_H
