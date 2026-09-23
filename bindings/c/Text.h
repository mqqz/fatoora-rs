#ifndef Text_H
#define Text_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"

#include "Text.d.h"






typedef struct fatoora_Text_value_result {union { BindingError* err;}; bool is_ok;} fatoora_Text_value_result;
fatoora_Text_value_result fatoora_Text_value(const Text* self, DiplomatWrite* write);

void fatoora_Text_destroy(Text* self);





#endif // Text_H
