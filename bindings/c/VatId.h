#ifndef VatId_H
#define VatId_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"

#include "VatId.d.h"






typedef struct fatoora_VatId_value_result {union { BindingError* err;}; bool is_ok;} fatoora_VatId_value_result;
fatoora_VatId_value_result fatoora_VatId_value(const VatId* self, DiplomatWrite* write);

void fatoora_VatId_destroy(VatId* self);





#endif // VatId_H
