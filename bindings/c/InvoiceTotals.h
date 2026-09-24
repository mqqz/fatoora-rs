#ifndef InvoiceTotals_H
#define InvoiceTotals_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"

#include "InvoiceTotals.d.h"






typedef struct fatoora_InvoiceTotals_tax_inclusive_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_tax_inclusive_result;
fatoora_InvoiceTotals_tax_inclusive_result fatoora_InvoiceTotals_tax_inclusive(const InvoiceTotals* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceTotals_tax_amount_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_tax_amount_result;
fatoora_InvoiceTotals_tax_amount_result fatoora_InvoiceTotals_tax_amount(const InvoiceTotals* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceTotals_line_extension_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_line_extension_result;
fatoora_InvoiceTotals_line_extension_result fatoora_InvoiceTotals_line_extension(const InvoiceTotals* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceTotals_allowance_total_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_allowance_total_result;
fatoora_InvoiceTotals_allowance_total_result fatoora_InvoiceTotals_allowance_total(const InvoiceTotals* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceTotals_charge_total_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_charge_total_result;
fatoora_InvoiceTotals_charge_total_result fatoora_InvoiceTotals_charge_total(const InvoiceTotals* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceTotals_taxable_amount_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_taxable_amount_result;
fatoora_InvoiceTotals_taxable_amount_result fatoora_InvoiceTotals_taxable_amount(const InvoiceTotals* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceTotals_prepaid_amount_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_prepaid_amount_result;
fatoora_InvoiceTotals_prepaid_amount_result fatoora_InvoiceTotals_prepaid_amount(const InvoiceTotals* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceTotals_payable_rounding_amount_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_payable_rounding_amount_result;
fatoora_InvoiceTotals_payable_rounding_amount_result fatoora_InvoiceTotals_payable_rounding_amount(const InvoiceTotals* self, DiplomatWrite* write);

typedef struct fatoora_InvoiceTotals_payable_amount_result {union { BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_payable_amount_result;
fatoora_InvoiceTotals_payable_amount_result fatoora_InvoiceTotals_payable_amount(const InvoiceTotals* self, DiplomatWrite* write);

void fatoora_InvoiceTotals_destroy(InvoiceTotals* self);





#endif // InvoiceTotals_H
