#ifndef Bytes_H
#define Bytes_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "diplomat_runtime.h"


#include "Bytes.d.h"






DiplomatU8View fatoora_Bytes_as_slice(const Bytes* self);

void fatoora_Bytes_destroy(Bytes* self);





#endif // Bytes_H
