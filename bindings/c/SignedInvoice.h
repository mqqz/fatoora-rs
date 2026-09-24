#ifndef SignedInvoice_H
#define SignedInvoice_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "InvoiceData.d.h"
#include "InvoiceTotals.d.h"
#include "Text.d.h"

#include "SignedInvoice.d.h"






typedef struct fatoora_SignedInvoice_from_xml_result {union {SignedInvoice* ok; BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_from_xml_result;
fatoora_SignedInvoice_from_xml_result fatoora_SignedInvoice_from_xml(DiplomatStringView value);

typedef struct fatoora_SignedInvoice_from_file_result {union {SignedInvoice* ok; BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_from_file_result;
fatoora_SignedInvoice_from_file_result fatoora_SignedInvoice_from_file(DiplomatStringView value);

typedef struct fatoora_SignedInvoice_data_result {union {InvoiceData* ok; BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_data_result;
fatoora_SignedInvoice_data_result fatoora_SignedInvoice_data(const SignedInvoice* self);

typedef struct fatoora_SignedInvoice_totals_result {union {InvoiceTotals* ok; BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_totals_result;
fatoora_SignedInvoice_totals_result fatoora_SignedInvoice_totals(const SignedInvoice* self);

typedef struct fatoora_SignedInvoice_hash_base64_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_hash_base64_result;
fatoora_SignedInvoice_hash_base64_result fatoora_SignedInvoice_hash_base64(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_xml_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_xml_result;
fatoora_SignedInvoice_xml_result fatoora_SignedInvoice_xml(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_qr_code_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_qr_code_result;
fatoora_SignedInvoice_qr_code_result fatoora_SignedInvoice_qr_code(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_signature_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_signature_result;
fatoora_SignedInvoice_signature_result fatoora_SignedInvoice_signature(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_public_key_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_public_key_result;
fatoora_SignedInvoice_public_key_result fatoora_SignedInvoice_public_key(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_invoice_hash_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_invoice_hash_result;
fatoora_SignedInvoice_invoice_hash_result fatoora_SignedInvoice_invoice_hash(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_to_xml_base64_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_to_xml_base64_result;
fatoora_SignedInvoice_to_xml_base64_result fatoora_SignedInvoice_to_xml_base64(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_issuer_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_issuer_result;
fatoora_SignedInvoice_issuer_result fatoora_SignedInvoice_issuer(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_serial_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_serial_result;
fatoora_SignedInvoice_serial_result fatoora_SignedInvoice_serial(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_cert_hash_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_cert_hash_result;
fatoora_SignedInvoice_cert_hash_result fatoora_SignedInvoice_cert_hash(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_signed_props_hash_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_signed_props_hash_result;
fatoora_SignedInvoice_signed_props_hash_result fatoora_SignedInvoice_signed_props_hash(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_signing_time_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_signing_time_result;
fatoora_SignedInvoice_signing_time_result fatoora_SignedInvoice_signing_time(const SignedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_SignedInvoice_zatca_key_signature_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_zatca_key_signature_result;
fatoora_SignedInvoice_zatca_key_signature_result fatoora_SignedInvoice_zatca_key_signature(const SignedInvoice* self);

typedef struct fatoora_SignedInvoice_into_xml_result {union { BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_into_xml_result;
fatoora_SignedInvoice_into_xml_result fatoora_SignedInvoice_into_xml(SignedInvoice* self, DiplomatWrite* write);

void fatoora_SignedInvoice_destroy(SignedInvoice* self);





#endif // SignedInvoice_H
