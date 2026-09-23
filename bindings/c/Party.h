#ifndef Party_H
#define Party_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "Address.d.h"
#include "BindingError.d.h"
#include "OtherId.d.h"
#include "VatId.d.h"

#include "Party.d.h"






typedef struct fatoora_Party_address_result {union {Address* ok; BindingError* err;}; bool is_ok;} fatoora_Party_address_result;
fatoora_Party_address_result fatoora_Party_address(const Party* self);

typedef struct fatoora_Party_vat_id_result {union {VatId* ok; BindingError* err;}; bool is_ok;} fatoora_Party_vat_id_result;
fatoora_Party_vat_id_result fatoora_Party_vat_id(const Party* self);

typedef struct fatoora_Party_other_id_result {union {OtherId* ok; BindingError* err;}; bool is_ok;} fatoora_Party_other_id_result;
fatoora_Party_other_id_result fatoora_Party_other_id(const Party* self);

typedef struct fatoora_Party_name_result {union { BindingError* err;}; bool is_ok;} fatoora_Party_name_result;
fatoora_Party_name_result fatoora_Party_name(const Party* self, DiplomatWrite* write);

void fatoora_Party_destroy(Party* self);





#endif // Party_H
