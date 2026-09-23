#ifndef CsrProperties_H
#define CsrProperties_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Csr.d.h"
#include "SigningKey.d.h"

#include "CsrProperties.d.h"






typedef struct fatoora_CsrProperties_new_result {union {CsrProperties* ok; BindingError* err;}; bool is_ok;} fatoora_CsrProperties_new_result;
fatoora_CsrProperties_new_result fatoora_CsrProperties_new(DiplomatStringView common_name, DiplomatStringView serial_number, DiplomatStringView organization_identifier, DiplomatStringView organization_unit_name, DiplomatStringView organization_name, DiplomatStringView country_name, DiplomatStringView invoice_type, DiplomatStringView location_address, DiplomatStringView industry_business_category);

typedef struct fatoora_CsrProperties_from_properties_str_result {union {CsrProperties* ok; BindingError* err;}; bool is_ok;} fatoora_CsrProperties_from_properties_str_result;
fatoora_CsrProperties_from_properties_str_result fatoora_CsrProperties_from_properties_str(DiplomatStringView properties);

typedef struct fatoora_CsrProperties_parse_csr_config_file_result {union {CsrProperties* ok; BindingError* err;}; bool is_ok;} fatoora_CsrProperties_parse_csr_config_file_result;
fatoora_CsrProperties_parse_csr_config_file_result fatoora_CsrProperties_parse_csr_config_file(DiplomatStringView path);

typedef struct fatoora_CsrProperties_build_result {union {Csr* ok; BindingError* err;}; bool is_ok;} fatoora_CsrProperties_build_result;
fatoora_CsrProperties_build_result fatoora_CsrProperties_build(const CsrProperties* self, const SigningKey* key, uint8_t env);

void fatoora_CsrProperties_destroy(CsrProperties* self);





#endif // CsrProperties_H
