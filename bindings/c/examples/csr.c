/* --8<-- [start:example] */
#include "fatoora/csr.h"

#include <assert.h>
#include <string.h>

#ifndef FATOORA_DOC_CSR_PROPS
#define FATOORA_DOC_CSR_PROPS "path/to/csr.properties"
#endif

int main(void) {
    const char *csr_props_path = FATOORA_DOC_CSR_PROPS;
    struct FfiResult_FfiCsrProperties props =
        fatoora_csr_properties_parse_csr_config_file(csr_props_path);
    if (!props.ok) {
        /* handle error */
        return 1;
    }

    struct FfiResult_FfiSigningKey key =
        fatoora_signing_key_generate();
    if (!key.ok) {
        /* handle error */
        return 1;
    }

    struct FfiResult_FfiCsr csr =
        fatoora_csr_build(&props.value, &key.value, FfiEnvironment_NonProduction);
    if (!csr.ok) {
        /* handle error */
        return 1;
    }

    struct FfiResult_FfiString csr_b64 = fatoora_csr_to_base64(&csr.value);
    struct FfiResult_FfiString key_pem = fatoora_signing_key_to_pem(&key.value);
    assert(csr_b64.value.ptr && strlen(csr_b64.value.ptr) > 0);
    assert(key_pem.value.ptr && strstr(key_pem.value.ptr, "BEGIN PRIVATE KEY"));
    /* use csr_b64.value.ptr and key_pem.value.ptr, then free */
    fatoora_string_free(csr_b64.value);
    fatoora_string_free(key_pem.value);
    fatoora_csr_free(&csr.value);
    fatoora_signing_key_free(&key.value);
    fatoora_csr_properties_free(&props.value);
    return 0;
}
/* --8<-- [end:example] */
