#ifndef Xml_H
#define Xml_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"

#include "BindingError.d.h"
#include "Config.d.h"

#include "Xml.d.h"






typedef struct fatoora_Xml_validate_result {union {bool ok; BindingError* err;}; bool is_ok;} fatoora_Xml_validate_result;
fatoora_Xml_validate_result fatoora_Xml_validate(const Config* config, DiplomatStringView xml);

typedef struct fatoora_Xml_hash_result {union { BindingError* err;}; bool is_ok;} fatoora_Xml_hash_result;
fatoora_Xml_hash_result fatoora_Xml_hash(DiplomatStringView xml, DiplomatWrite* write);

void fatoora_Xml_destroy(Xml* self);





#endif // Xml_H
