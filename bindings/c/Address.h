#ifndef Address_H
#define Address_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Text.d.h"

#include "Address.d.h"






typedef struct fatoora_Address_new_result {union {Address* ok; BindingError* err;}; bool is_ok;} fatoora_Address_new_result;
fatoora_Address_new_result fatoora_Address_new(DiplomatStringView country_code, DiplomatStringView city, DiplomatStringView street, DiplomatStringView building_number, DiplomatStringView postal_code, OptionStringView additional_street, OptionStringView additional_number, OptionStringView district);

typedef struct fatoora_Address_city_result {union { BindingError* err;}; bool is_ok;} fatoora_Address_city_result;
fatoora_Address_city_result fatoora_Address_city(const Address* self, DiplomatWrite* write);

typedef struct fatoora_Address_street_result {union { BindingError* err;}; bool is_ok;} fatoora_Address_street_result;
fatoora_Address_street_result fatoora_Address_street(const Address* self, DiplomatWrite* write);

typedef struct fatoora_Address_building_number_result {union { BindingError* err;}; bool is_ok;} fatoora_Address_building_number_result;
fatoora_Address_building_number_result fatoora_Address_building_number(const Address* self, DiplomatWrite* write);

typedef struct fatoora_Address_postal_code_result {union { BindingError* err;}; bool is_ok;} fatoora_Address_postal_code_result;
fatoora_Address_postal_code_result fatoora_Address_postal_code(const Address* self, DiplomatWrite* write);

typedef struct fatoora_Address_country_code_result {union { BindingError* err;}; bool is_ok;} fatoora_Address_country_code_result;
fatoora_Address_country_code_result fatoora_Address_country_code(const Address* self, DiplomatWrite* write);

typedef struct fatoora_Address_additional_street_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_Address_additional_street_result;
fatoora_Address_additional_street_result fatoora_Address_additional_street(const Address* self);

typedef struct fatoora_Address_additional_number_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_Address_additional_number_result;
fatoora_Address_additional_number_result fatoora_Address_additional_number(const Address* self);

typedef struct fatoora_Address_district_result {union {Text* ok; BindingError* err;}; bool is_ok;} fatoora_Address_district_result;
fatoora_Address_district_result fatoora_Address_district(const Address* self);

void fatoora_Address_destroy(Address* self);





#endif // Address_H
