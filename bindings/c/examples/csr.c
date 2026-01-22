/* --8<-- [start:example] */
#include "fatoora/csr.h"

#include <assert.h>
#include <string.h>

#ifndef FATOORA_DOC_CSR_PROPS
#define FATOORA_DOC_CSR_PROPS "path/to/csr.properties"
#endif
int main(void) {
    const char *csr_props_path = FATOORA_DOC_CSR_PROPS;
    struct FfiResult_FfiCsrProperties props = fatoora_csr_properties_parse(csr_props_path);
    if (!props.ok) {
        /* handle error */
        return 1;
    }

    struct FfiResult_FfiCsrBundle bundle =
        fatoora_csr_build_with_rng(&props.value, FfiEnvironment_NonProduction);
    if (!bundle.ok) {
        /* handle error */
        return 1;
    }

    struct FfiResult_FfiString csr_b64 = fatoora_csr_to_base64(&bundle.value.csr);
    struct FfiResult_FfiString key_pem = fatoora_signing_key_to_pem(&bundle.value.key);
    assert(csr_b64.value.ptr && strlen(csr_b64.value.ptr) > 0);
    assert(key_pem.value.ptr && strstr(key_pem.value.ptr, "BEGIN PRIVATE KEY"));
    /* use csr_b64.value.ptr and key_pem.value.ptr, then free */
    fatoora_string_free(csr_b64.value);
    fatoora_string_free(key_pem.value);
    fatoora_csr_free(&bundle.value.csr);
    fatoora_signing_key_free(&bundle.value.key);
    fatoora_csr_properties_free(&props.value);
    return 0;
}
/* --8<-- [end:example] */
