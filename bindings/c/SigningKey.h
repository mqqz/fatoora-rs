#ifndef SigningKey_H
#define SigningKey_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Bytes.d.h"

#include "SigningKey.d.h"






typedef struct fatoora_SigningKey_generate_result {union {SigningKey* ok; BindingError* err;}; bool is_ok;} fatoora_SigningKey_generate_result;
fatoora_SigningKey_generate_result fatoora_SigningKey_generate(void);

typedef struct fatoora_SigningKey_from_pem_result {union {SigningKey* ok; BindingError* err;}; bool is_ok;} fatoora_SigningKey_from_pem_result;
fatoora_SigningKey_from_pem_result fatoora_SigningKey_from_pem(DiplomatStringView pem);

typedef struct fatoora_SigningKey_from_der_result {union {SigningKey* ok; BindingError* err;}; bool is_ok;} fatoora_SigningKey_from_der_result;
fatoora_SigningKey_from_der_result fatoora_SigningKey_from_der(DiplomatU8View der);

typedef struct fatoora_SigningKey_to_pem_result {union { BindingError* err;}; bool is_ok;} fatoora_SigningKey_to_pem_result;
fatoora_SigningKey_to_pem_result fatoora_SigningKey_to_pem(const SigningKey* self, DiplomatWrite* write);

typedef struct fatoora_SigningKey_to_der_result {union {Bytes* ok; BindingError* err;}; bool is_ok;} fatoora_SigningKey_to_der_result;
fatoora_SigningKey_to_der_result fatoora_SigningKey_to_der(const SigningKey* self);

void fatoora_SigningKey_destroy(SigningKey* self);





#endif // SigningKey_H
