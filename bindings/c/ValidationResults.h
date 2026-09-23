#ifndef ValidationResults_H
#define ValidationResults_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Text.d.h"
#include "ValidationMessage.d.h"

#include "ValidationResults.d.h"






typedef struct fatoora_ValidationResults_status_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResults_status_result;
fatoora_ValidationResults_status_result fatoora_ValidationResults_status(const ValidationResults* self);

size_t fatoora_ValidationResults_info_len(const ValidationResults* self);

typedef struct fatoora_ValidationResults_info_message_result {union {ValidationMessage* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResults_info_message_result;
fatoora_ValidationResults_info_message_result fatoora_ValidationResults_info_message(const ValidationResults* self, size_t index);

size_t fatoora_ValidationResults_warning_len(const ValidationResults* self);

typedef struct fatoora_ValidationResults_warning_message_result {union {ValidationMessage* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResults_warning_message_result;
fatoora_ValidationResults_warning_message_result fatoora_ValidationResults_warning_message(const ValidationResults* self, size_t index);

size_t fatoora_ValidationResults_error_len(const ValidationResults* self);

typedef struct fatoora_ValidationResults_error_message_result {union {ValidationMessage* ok; BindingError* err;}; bool is_ok;} fatoora_ValidationResults_error_message_result;
fatoora_ValidationResults_error_message_result fatoora_ValidationResults_error_message(const ValidationResults* self, size_t index);

void fatoora_ValidationResults_destroy(ValidationResults* self);





#endif // ValidationResults_H
