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
    /* Compile and exercise the exact response accessor ABI in C and C++. */
    struct FfiResult_u16 status = fatoora_validation_response_http_status(NULL);
    struct FfiResult_u8 outcome = fatoora_validation_response_outcome(NULL);
    struct FfiResult_bool accepted = fatoora_validation_response_ensure_accepted(NULL);
    struct FfiResult_FfiString encoded = fatoora_validation_response_cleared_invoice_base64(NULL);
    struct FfiResult_FfiString xml = fatoora_validation_response_cleared_invoice_xml(NULL);
    assert(!status.ok && !outcome.ok && !accepted.ok && !encoded.ok && !xml.ok);
    fatoora_error_free(status.error);
    fatoora_error_free(outcome.error);
    fatoora_error_free(accepted.error);
    fatoora_error_free(encoded.error);
    fatoora_error_free(xml.error);
    return 0;
}
