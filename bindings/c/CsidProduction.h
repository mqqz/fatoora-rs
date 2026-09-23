#ifndef CsidProduction_H
#define CsidProduction_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Text.d.h"

#include "CsidProduction.d.h"






typedef struct fatoora_CsidProduction_create_result {union {CsidProduction* ok; BindingError* err;}; bool is_ok;} fatoora_CsidProduction_create_result;
fatoora_CsidProduction_create_result fatoora_CsidProduction_create(uint8_t environment, OptionStringView request_id, DiplomatStringView token, DiplomatStringView secret);

uint8_t fatoora_CsidProduction_env(const CsidProduction* self);

typedef struct fatoora_CsidProduction_request_id_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_CsidProduction_request_id_result;
fatoora_CsidProduction_request_id_result fatoora_CsidProduction_request_id(const CsidProduction* self);

typedef struct fatoora_CsidProduction_binary_security_token_result {union { BindingError* err;}; bool is_ok;} fatoora_CsidProduction_binary_security_token_result;
fatoora_CsidProduction_binary_security_token_result fatoora_CsidProduction_binary_security_token(const CsidProduction* self, DiplomatWrite* write);

typedef struct fatoora_CsidProduction_secret_result {union { BindingError* err;}; bool is_ok;} fatoora_CsidProduction_secret_result;
fatoora_CsidProduction_secret_result fatoora_CsidProduction_secret(const CsidProduction* self, DiplomatWrite* write);

void fatoora_CsidProduction_destroy(CsidProduction* self);





#endif // CsidProduction_H
