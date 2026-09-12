/* Run against a built shared library; see docs/development/ffi-workflow.md. */
#include "fatoora.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    struct FfiConfig *config = fatoora_config_new(FfiEnvironment_NonProduction);
    assert(config != NULL);
    struct FfiResult_bool result = fatoora_validate_xml_invoice_from_str(config, "<Invoice/>");
    assert(!result.ok);
    assert(result.error != NULL);
    assert(fatoora_error_code(result.error) == 2);
#ifdef FATOORA_FFI_NO_PREFIX
    Error *error = result.error;
    assert(error_code(error) == ErrorKind_Validation);
#endif
    struct FfiString message = fatoora_error_message(result.error);
    struct FfiString details = fatoora_error_details_json(result.error);
    fatoora_error_free(result.error);
    fatoora_config_free(config);

    /* Both copies remain usable after their error and config have been freed. */
    assert(message.ptr != NULL && strlen(message.ptr) > 0);
    assert(details.ptr != NULL);
    assert(strstr(details.ptr, "\"type\":\"schema_validation\"") != NULL);
    assert(strstr(details.ptr, "\"diagnostics\":") != NULL);
    puts(details.ptr);
    fatoora_string_free(message);
    fatoora_string_free(details);
    assert(fatoora_error_code(NULL) == 0);
    assert(fatoora_error_message(NULL).ptr == NULL);
    assert(fatoora_error_details_json(NULL).ptr == NULL);
    fatoora_error_free(NULL);
    return 0;
}
