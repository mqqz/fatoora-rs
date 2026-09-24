#ifndef InvoiceNote_H
#define InvoiceNote_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"

#include "InvoiceNote.d.h"






typedef struct fatoora_InvoiceNote_language_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceNote_language_result;
fatoora_InvoiceNote_language_result fatoora_InvoiceNote_language(const InvoiceNote* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceNote_text_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceNote_text_result;
fatoora_InvoiceNote_text_result fatoora_InvoiceNote_text(const InvoiceNote* self, DiplomatWrite* write);

void fatoora_InvoiceNote_destroy(InvoiceNote* self);





#endif // InvoiceNote_H
