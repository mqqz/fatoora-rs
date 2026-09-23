#ifndef InvoiceLineItem_H
#define InvoiceLineItem_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"

#include "InvoiceLineItem.d.h"






typedef struct fatoora_InvoiceLineItem_description_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_description_result;
fatoora_InvoiceLineItem_description_result fatoora_InvoiceLineItem_description(const InvoiceLineItem* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceLineItem_unit_code_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_unit_code_result;
fatoora_InvoiceLineItem_unit_code_result fatoora_InvoiceLineItem_unit_code(const InvoiceLineItem* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceLineItem_quantity_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_quantity_result;
fatoora_InvoiceLineItem_quantity_result fatoora_InvoiceLineItem_quantity(const InvoiceLineItem* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceLineItem_unit_price_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_unit_price_result;
fatoora_InvoiceLineItem_unit_price_result fatoora_InvoiceLineItem_unit_price(const InvoiceLineItem* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceLineItem_total_amount_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_total_amount_result;
fatoora_InvoiceLineItem_total_amount_result fatoora_InvoiceLineItem_total_amount(const InvoiceLineItem* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceLineItem_vat_rate_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_vat_rate_result;
fatoora_InvoiceLineItem_vat_rate_result fatoora_InvoiceLineItem_vat_rate(const InvoiceLineItem* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceLineItem_vat_amount_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_vat_amount_result;
fatoora_InvoiceLineItem_vat_amount_result fatoora_InvoiceLineItem_vat_amount(const InvoiceLineItem* self, DiplomatWrite* write);

uint8_t fatoora_InvoiceLineItem_vat_category(const InvoiceLineItem* self);

void fatoora_InvoiceLineItem_destroy(InvoiceLineItem* self);





#endif // InvoiceLineItem_H
