#ifndef FinalizedInvoice_H
#define FinalizedInvoice_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "InvoiceData.d.h"
#include "InvoiceTotals.d.h"

#include "FinalizedInvoice.d.h"






typedef struct fatoora_FinalizedInvoice_from_xml_result {union {FinalizedInvoice* ok; BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_from_xml_result;
fatoora_FinalizedInvoice_from_xml_result fatoora_FinalizedInvoice_from_xml(DiplomatStringView value);

typedef struct fatoora_FinalizedInvoice_from_file_result {union {FinalizedInvoice* ok; BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_from_file_result;
fatoora_FinalizedInvoice_from_file_result fatoora_FinalizedInvoice_from_file(DiplomatStringView value);

typedef struct fatoora_FinalizedInvoice_data_result {union {InvoiceData* ok; BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_data_result;
fatoora_FinalizedInvoice_data_result fatoora_FinalizedInvoice_data(const FinalizedInvoice* self);

typedef struct fatoora_FinalizedInvoice_totals_result {union {InvoiceTotals* ok; BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_totals_result;
fatoora_FinalizedInvoice_totals_result fatoora_FinalizedInvoice_totals(const FinalizedInvoice* self);

typedef struct fatoora_FinalizedInvoice_hash_base64_result {union { BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_hash_base64_result;
fatoora_FinalizedInvoice_hash_base64_result fatoora_FinalizedInvoice_hash_base64(const FinalizedInvoice* self, DiplomatWrite* write);

typedef struct fatoora_FinalizedInvoice_xml_result {union { BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_xml_result;
fatoora_FinalizedInvoice_xml_result fatoora_FinalizedInvoice_xml(const FinalizedInvoice* self, DiplomatWrite* write);

void fatoora_FinalizedInvoice_destroy(FinalizedInvoice* self);





#endif // FinalizedInvoice_H
