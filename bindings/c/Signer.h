#ifndef Signer_H
#define Signer_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Bytes.d.h"
#include "FinalizedInvoice.d.h"
#include "SignedInvoice.d.h"

#include "Signer.d.h"






typedef struct fatoora_Signer_from_pem_result {union {Signer* ok; BindingError* err;}; bool is_ok;} fatoora_Signer_from_pem_result;
fatoora_Signer_from_pem_result fatoora_Signer_from_pem(DiplomatStringView cert_pem, DiplomatStringView key_pem);

typedef struct fatoora_Signer_from_der_result {union {Signer* ok; BindingError* err;}; bool is_ok;} fatoora_Signer_from_der_result;
fatoora_Signer_from_der_result fatoora_Signer_from_der(DiplomatU8View cert_der, DiplomatU8View key_der);

typedef struct fatoora_Signer_certificate_der_result {union {Bytes* ok; BindingError* err;}; bool is_ok;} fatoora_Signer_certificate_der_result;
fatoora_Signer_certificate_der_result fatoora_Signer_certificate_der(const Signer* self);

typedef struct fatoora_Signer_certificate_pem_result {union { BindingError* err;}; bool is_ok;} fatoora_Signer_certificate_pem_result;
fatoora_Signer_certificate_pem_result fatoora_Signer_certificate_pem(const Signer* self, DiplomatWrite* write);

typedef struct fatoora_Signer_sign_result {union {SignedInvoice* ok; BindingError* err;}; bool is_ok;} fatoora_Signer_sign_result;
fatoora_Signer_sign_result fatoora_Signer_sign(const Signer* self, FinalizedInvoice* invoice);

typedef struct fatoora_Signer_sign_xml_result {union { BindingError* err;}; bool is_ok;} fatoora_Signer_sign_xml_result;
fatoora_Signer_sign_xml_result fatoora_Signer_sign_xml(const Signer* self, DiplomatStringView xml, DiplomatWrite* write);

void fatoora_Signer_destroy(Signer* self);





#endif // Signer_H
