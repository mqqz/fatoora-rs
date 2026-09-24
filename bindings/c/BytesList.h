#ifndef BytesList_H
#define BytesList_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Bytes.d.h"

#include "BytesList.d.h"






size_t fatoora_BytesList_len(const BytesList* self);

bool fatoora_BytesList_is_empty(const BytesList* self);

typedef struct fatoora_BytesList_get_result {union {Bytes* ok; BindingError* err;}; bool is_ok;} fatoora_BytesList_get_result;
fatoora_BytesList_get_result fatoora_BytesList_get(const BytesList* self, size_t index);

void fatoora_BytesList_destroy(BytesList* self);





#endif // BytesList_H
