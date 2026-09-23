#ifndef InvoiceBuilder_H
#define InvoiceBuilder_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "Address.d.h"
#include "BindingError.d.h"
#include "FinalizedInvoice.d.h"

#include "InvoiceBuilder.d.h"






typedef struct fatoora_InvoiceBuilder_new_result {union {InvoiceBuilder* ok; BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_new_result;
fatoora_InvoiceBuilder_new_result fatoora_InvoiceBuilder_new(uint8_t kind, uint8_t subtype, OptionStringView original_id, OptionStringView original_uuid, OptionStringView original_date, OptionStringView reason);

typedef struct fatoora_InvoiceBuilder_set_id_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_id_result;
fatoora_InvoiceBuilder_set_id_result fatoora_InvoiceBuilder_set_id(InvoiceBuilder* self, DiplomatStringView value);

typedef struct fatoora_InvoiceBuilder_set_uuid_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_uuid_result;
fatoora_InvoiceBuilder_set_uuid_result fatoora_InvoiceBuilder_set_uuid(InvoiceBuilder* self, DiplomatStringView value);

typedef struct fatoora_InvoiceBuilder_set_issue_datetime_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_issue_datetime_result;
fatoora_InvoiceBuilder_set_issue_datetime_result fatoora_InvoiceBuilder_set_issue_datetime(InvoiceBuilder* self, DiplomatStringView value);

typedef struct fatoora_InvoiceBuilder_set_currency_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_currency_result;
fatoora_InvoiceBuilder_set_currency_result fatoora_InvoiceBuilder_set_currency(InvoiceBuilder* self, DiplomatStringView value);

typedef struct fatoora_InvoiceBuilder_set_previous_invoice_hash_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_previous_invoice_hash_result;
fatoora_InvoiceBuilder_set_previous_invoice_hash_result fatoora_InvoiceBuilder_set_previous_invoice_hash(InvoiceBuilder* self, DiplomatStringView value);

typedef struct fatoora_InvoiceBuilder_set_payment_means_code_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_payment_means_code_result;
fatoora_InvoiceBuilder_set_payment_means_code_result fatoora_InvoiceBuilder_set_payment_means_code(InvoiceBuilder* self, DiplomatStringView value);

typedef struct fatoora_InvoiceBuilder_allowance_reason_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_allowance_reason_result;
fatoora_InvoiceBuilder_allowance_reason_result fatoora_InvoiceBuilder_allowance_reason(InvoiceBuilder* self, DiplomatStringView value);

typedef struct fatoora_InvoiceBuilder_invoice_level_charge_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_invoice_level_charge_result;
fatoora_InvoiceBuilder_invoice_level_charge_result fatoora_InvoiceBuilder_invoice_level_charge(InvoiceBuilder* self, DiplomatStringView value);

typedef struct fatoora_InvoiceBuilder_invoice_level_discount_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_invoice_level_discount_result;
fatoora_InvoiceBuilder_invoice_level_discount_result fatoora_InvoiceBuilder_invoice_level_discount(InvoiceBuilder* self, DiplomatStringView value);

typedef struct fatoora_InvoiceBuilder_set_invoice_counter_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_invoice_counter_result;
fatoora_InvoiceBuilder_set_invoice_counter_result fatoora_InvoiceBuilder_set_invoice_counter(InvoiceBuilder* self, uint64_t value);

typedef struct fatoora_InvoiceBuilder_set_vat_category_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_vat_category_result;
fatoora_InvoiceBuilder_set_vat_category_result fatoora_InvoiceBuilder_set_vat_category(InvoiceBuilder* self, uint8_t value);

typedef struct fatoora_InvoiceBuilder_flags_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_flags_result;
fatoora_InvoiceBuilder_flags_result fatoora_InvoiceBuilder_flags(InvoiceBuilder* self, uint8_t value);

typedef struct fatoora_InvoiceBuilder_set_note_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_note_result;
fatoora_InvoiceBuilder_set_note_result fatoora_InvoiceBuilder_set_note(InvoiceBuilder* self, DiplomatStringView language, DiplomatStringView value);

typedef struct fatoora_InvoiceBuilder_set_allowance_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_allowance_result;
fatoora_InvoiceBuilder_set_allowance_result fatoora_InvoiceBuilder_set_allowance(InvoiceBuilder* self, DiplomatStringView reason, DiplomatStringView amount);

typedef struct fatoora_InvoiceBuilder_set_seller_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_seller_result;
fatoora_InvoiceBuilder_set_seller_result fatoora_InvoiceBuilder_set_seller(InvoiceBuilder* self, DiplomatStringView name, const Address* address, DiplomatStringView vat_id, OptionStringView other_id, OptionStringView scheme);

typedef struct fatoora_InvoiceBuilder_set_buyer_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_buyer_result;
fatoora_InvoiceBuilder_set_buyer_result fatoora_InvoiceBuilder_set_buyer(InvoiceBuilder* self, DiplomatStringView name, const Address* address, OptionStringView vat_id, OptionStringView other_id, OptionStringView scheme);

typedef struct fatoora_InvoiceBuilder_add_line_item_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_add_line_item_result;
fatoora_InvoiceBuilder_add_line_item_result fatoora_InvoiceBuilder_add_line_item(InvoiceBuilder* self, DiplomatStringView description, DiplomatStringView quantity, DiplomatStringView unit_code, DiplomatStringView unit_price, DiplomatStringView vat_rate, uint8_t category);

typedef struct fatoora_InvoiceBuilder_build_result {union {FinalizedInvoice* ok; BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_build_result;
fatoora_InvoiceBuilder_build_result fatoora_InvoiceBuilder_build(InvoiceBuilder* self);

void fatoora_InvoiceBuilder_destroy(InvoiceBuilder* self);





#endif // InvoiceBuilder_H
