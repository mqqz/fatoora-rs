/* Compile and run as C and C++ against the regenerated header and library. */
#include "fatoora.h"
#include <assert.h>
#include <string.h>

int main(void) {
    struct FfiResult_FfiAddress result = fatoora_address_new(
        "SA", "Riyadh", "King Fahd", "Second street", "1234", "0123", "12222", "Olaya");
    assert(result.ok);
    struct FfiResult_FfiString district = fatoora_address_district(&result.value);
    assert(district.ok);
    assert(strcmp(district.value.ptr, "Olaya") == 0);
    fatoora_address_free(&result.value);
    assert(strcmp(district.value.ptr, "Olaya") == 0);
    fatoora_string_free(district.value);
    return 0;
}
