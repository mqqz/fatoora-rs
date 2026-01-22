/* --8<-- [start:example] */
#include "fatoora/api.h"
#include "fatoora/invoice.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FATOORA_DOC_SIGNED_XML
#define FATOORA_DOC_SIGNED_XML "path/to/signed_invoice.xml"
#endif

static char *read_file(const char *path);

int main(void) {
    const char *signed_xml_path = FATOORA_DOC_SIGNED_XML;
    char *xml_cstr = read_file(signed_xml_path);
    if (!xml_cstr) {
        /* handle error */
        return 1;
    }

    struct FfiConfig *config = fatoora_config_new(FfiEnvironment_NonProduction);
    struct FfiResult_FfiZatcaClient client = fatoora_zatca_client_new(config);
    if (!client.ok) {
        /* handle error */
        return 1;
    }

    /* signed_xml_path = "path/to/signed_invoice.xml" */
    struct FfiResult_FfiSignedInvoice signed_invoice = fatoora_parse_signed_invoice_xml(xml_cstr);
    if (!signed_invoice.ok) {
        /* handle error */
        return 1;
    }

    struct FfiResult_FfiString hash = fatoora_signed_invoice_hash_base64(&signed_invoice.value);
    assert(hash.value.ptr && strlen(hash.value.ptr) > 0);
    fatoora_string_free(hash.value);

    struct FfiResult_FfiCsidCompliance ccsid =
        fatoora_csid_compliance_new(FfiEnvironment_NonProduction, true, 1234567890,
                                    "binary_security_token", "secret");
    if (!ccsid.ok) {
        /* handle error */
        return 1;
    }

    /* response handle provides getters for results */
    /* struct FfiResult_FfiValidationResponse resp =
       fatoora_zatca_check_compliance(&client.value, &signed_invoice.value, &ccsid.value); */
    free(xml_cstr);
    fatoora_signed_invoice_free(&signed_invoice.value);
    fatoora_csid_compliance_free(&ccsid.value);
    fatoora_zatca_client_free(&client.value);
    fatoora_config_free(config);
    return 0;
}
/* --8<-- [end:example] */

static char *read_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    char *buffer = malloc((size_t)size + 1);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }
    if (fread(buffer, 1, (size_t)size, fp) != (size_t)size) {
        fclose(fp);
        free(buffer);
        return NULL;
    }
    buffer[size] = '\0';
    fclose(fp);
    return buffer;
}
