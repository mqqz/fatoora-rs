#ifndef ValidationMessage_H
#define ValidationMessage_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Text.d.h"

#include "ValidationMessage.d.h"






typedef struct fatoora_ValidationMessage_message_type_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_message_type_result;
fatoora_ValidationMessage_message_type_result fatoora_ValidationMessage_message_type(const ValidationMessage* self);

typedef struct fatoora_ValidationMessage_code_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_code_result;
fatoora_ValidationMessage_code_result fatoora_ValidationMessage_code(const ValidationMessage* self);

typedef struct fatoora_ValidationMessage_category_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_category_result;
fatoora_ValidationMessage_category_result fatoora_ValidationMessage_category(const ValidationMessage* self);

typedef struct fatoora_ValidationMessage_message_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_message_result;
fatoora_ValidationMessage_message_result fatoora_ValidationMessage_message(const ValidationMessage* self);

typedef struct fatoora_ValidationMessage_status_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationMessage_status_result;
fatoora_ValidationMessage_status_result fatoora_ValidationMessage_status(const ValidationMessage* self);

void fatoora_ValidationMessage_destroy(ValidationMessage* self);





#endif // ValidationMessage_H
