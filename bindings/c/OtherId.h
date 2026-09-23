#ifndef OtherId_H
#define OtherId_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Text.d.h"

#include "OtherId.d.h"






typedef struct fatoora_OtherId_value_result {union { BindingError* err;}; bool is_ok;} fatoora_OtherId_value_result;
fatoora_OtherId_value_result fatoora_OtherId_value(const OtherId* self, DiplomatWrite* write);

typedef struct fatoora_OtherId_scheme_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_OtherId_scheme_result;
fatoora_OtherId_scheme_result fatoora_OtherId_scheme(const OtherId* self);

void fatoora_OtherId_destroy(OtherId* self);





#endif // OtherId_H
