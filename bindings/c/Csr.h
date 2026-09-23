#ifndef Csr_H
#define Csr_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Bytes.d.h"
#include "BytesList.d.h"

#include "Csr.d.h"






typedef struct fatoora_Csr_from_der_result {union {Csr* ok; BindingError* err;}; bool is_ok;} fatoora_Csr_from_der_result;
fatoora_Csr_from_der_result fatoora_Csr_from_der(DiplomatU8View der);

typedef struct fatoora_Csr_to_der_result {union {Bytes* ok; BindingError* err;}; bool is_ok;} fatoora_Csr_to_der_result;
fatoora_Csr_to_der_result fatoora_Csr_to_der(const Csr* self);

typedef struct fatoora_Csr_to_pem_result {union { BindingError* err;}; bool is_ok;} fatoora_Csr_to_pem_result;
fatoora_Csr_to_pem_result fatoora_Csr_to_pem(const Csr* self, DiplomatWrite* write);

typedef struct fatoora_Csr_to_base64_result {union { BindingError* err;}; bool is_ok;} fatoora_Csr_to_base64_result;
fatoora_Csr_to_base64_result fatoora_Csr_to_base64(const Csr* self, DiplomatWrite* write);

typedef struct fatoora_Csr_to_pem_base64_result {union { BindingError* err;}; bool is_ok;} fatoora_Csr_to_pem_base64_result;
fatoora_Csr_to_pem_base64_result fatoora_Csr_to_pem_base64(const Csr* self, DiplomatWrite* write);

typedef struct fatoora_Csr_subject_string_result {union { BindingError* err;}; bool is_ok;} fatoora_Csr_subject_string_result;
fatoora_Csr_subject_string_result fatoora_Csr_subject_string(const Csr* self, DiplomatWrite* write);

typedef struct fatoora_Csr_extension_values_der_result {union {BytesList* ok; BindingError* err;}; bool is_ok;} fatoora_Csr_extension_values_der_result;
fatoora_Csr_extension_values_der_result fatoora_Csr_extension_values_der(const Csr* self);

void fatoora_Csr_destroy(Csr* self);





#endif // Csr_H
