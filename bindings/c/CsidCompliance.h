#ifndef CsidCompliance_H
#define CsidCompliance_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Text.d.h"

#include "CsidCompliance.d.h"






typedef struct fatoora_CsidCompliance_create_result {union {CsidCompliance* ok; BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_create_result;
fatoora_CsidCompliance_create_result fatoora_CsidCompliance_create(uint8_t environment, OptionStringView request_id, DiplomatStringView token, DiplomatStringView secret);

uint8_t fatoora_CsidCompliance_env(const CsidCompliance* self);

typedef struct fatoora_CsidCompliance_request_id_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_request_id_result;
fatoora_CsidCompliance_request_id_result fatoora_CsidCompliance_request_id(const CsidCompliance* self);

typedef struct fatoora_CsidCompliance_binary_security_token_result {union { BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_binary_security_token_result;
fatoora_CsidCompliance_binary_security_token_result fatoora_CsidCompliance_binary_security_token(const CsidCompliance* self, DiplomatWrite* write);

typedef struct fatoora_CsidCompliance_secret_result {union { BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_secret_result;
fatoora_CsidCompliance_secret_result fatoora_CsidCompliance_secret(const CsidCompliance* self, DiplomatWrite* write);

void fatoora_CsidCompliance_destroy(CsidCompliance* self);





#endif // CsidCompliance_H
