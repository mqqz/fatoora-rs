#ifndef BindingError_H
#define BindingError_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"


#include "BindingError.d.h"






int32_t fatoora_BindingError_code(const BindingError* self);

void fatoora_BindingError_message(const BindingError* self, DiplomatWrite* write);

void fatoora_BindingError_details_json(const BindingError* self, DiplomatWrite* write);

void fatoora_BindingError_destroy(BindingError* self);





#endif // BindingError_H
