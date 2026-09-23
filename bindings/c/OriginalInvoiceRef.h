#ifndef OriginalInvoiceRef_H
#define OriginalInvoiceRef_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Text.d.h"

#include "OriginalInvoiceRef.d.h"






typedef struct fatoora_OriginalInvoiceRef_id_result {union { BindingError* err;}; bool is_ok;} fatoora_OriginalInvoiceRef_id_result;
fatoora_OriginalInvoiceRef_id_result fatoora_OriginalInvoiceRef_id(const OriginalInvoiceRef* self, DiplomatWrite* write);

typedef struct fatoora_OriginalInvoiceRef_uuid_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_OriginalInvoiceRef_uuid_result;
fatoora_OriginalInvoiceRef_uuid_result fatoora_OriginalInvoiceRef_uuid(const OriginalInvoiceRef* self);

typedef struct fatoora_OriginalInvoiceRef_issue_date_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_OriginalInvoiceRef_issue_date_result;
fatoora_OriginalInvoiceRef_issue_date_result fatoora_OriginalInvoiceRef_issue_date(const OriginalInvoiceRef* self);

void fatoora_OriginalInvoiceRef_destroy(OriginalInvoiceRef* self);





#endif // OriginalInvoiceRef_H
