#ifndef Config_H
#define Config_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"

#include "Config.d.h"






typedef struct fatoora_Config_new_result {union {Config* ok; BindingError* err;}; bool is_ok;} fatoora_Config_new_result;
fatoora_Config_new_result fatoora_Config_new(uint8_t env);

uint8_t fatoora_Config_env(const Config* self);

void fatoora_Config_destroy(Config* self);





#endif // Config_H
