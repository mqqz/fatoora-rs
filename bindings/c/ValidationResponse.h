#ifndef ValidationResponse_H
#define ValidationResponse_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "InvoiceOutcome.d.h"
#include "Text.d.h"
#include "ValidationResults.d.h"

#include "ValidationResponse.d.h"






typedef struct fatoora_ValidationResponse_http_status_result {union {uint16_t ok; }; bool is_ok;} fatoora_ValidationResponse_http_status_result;
fatoora_ValidationResponse_http_status_result fatoora_ValidationResponse_http_status(const ValidationResponse* self);

InvoiceOutcome fatoora_ValidationResponse_outcome(const ValidationResponse* self);

typedef struct fatoora_ValidationResponse_ensure_accepted_result {union { BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_ensure_accepted_result;
fatoora_ValidationResponse_ensure_accepted_result fatoora_ValidationResponse_ensure_accepted(const ValidationResponse* self);

typedef struct fatoora_ValidationResponse_cleared_invoice_xml_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_cleared_invoice_xml_result;
fatoora_ValidationResponse_cleared_invoice_xml_result fatoora_ValidationResponse_cleared_invoice_xml(const ValidationResponse* self);

typedef struct fatoora_ValidationResponse_validation_results_result {union {ValidationResults* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_validation_results_result;
fatoora_ValidationResponse_validation_results_result fatoora_ValidationResponse_validation_results(const ValidationResponse* self);

typedef struct fatoora_ValidationResponse_cleared_invoice_base64_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_cleared_invoice_base64_result;
fatoora_ValidationResponse_cleared_invoice_base64_result fatoora_ValidationResponse_cleared_invoice_base64(const ValidationResponse* self);

typedef struct fatoora_ValidationResponse_reporting_status_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_reporting_status_result;
fatoora_ValidationResponse_reporting_status_result fatoora_ValidationResponse_reporting_status(const ValidationResponse* self);

typedef struct fatoora_ValidationResponse_clearance_status_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_clearance_status_result;
fatoora_ValidationResponse_clearance_status_result fatoora_ValidationResponse_clearance_status(const ValidationResponse* self);

typedef struct fatoora_ValidationResponse_qr_seller_status_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_qr_seller_status_result;
fatoora_ValidationResponse_qr_seller_status_result fatoora_ValidationResponse_qr_seller_status(const ValidationResponse* self);

typedef struct fatoora_ValidationResponse_qr_buyer_status_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_qr_buyer_status_result;
fatoora_ValidationResponse_qr_buyer_status_result fatoora_ValidationResponse_qr_buyer_status(const ValidationResponse* self);

void fatoora_ValidationResponse_destroy(ValidationResponse* self);





#endif // ValidationResponse_H
