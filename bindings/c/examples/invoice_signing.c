/* --8<-- [start:example] */
#include "fatoora/invoice.h"
#include "fatoora/sign.h"

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

    /* signed_xml_path = "path/to/signed_invoice.xml" */
    struct FfiResult_FfiSignedInvoice signed_invoice = fatoora_parse_signed_invoice_xml(xml_cstr);
    if (!signed_invoice.ok) {
        /* handle error */
        return 1;
    }
    struct FfiResult_FfiString hash = fatoora_signed_invoice_hash_base64(&signed_invoice.value);
    struct FfiResult_FfiString qr = fatoora_signed_invoice_qr_code(&signed_invoice.value);
    assert(hash.value.ptr && strlen(hash.value.ptr) > 0);
    assert(qr.value.ptr && strlen(qr.value.ptr) > 0);
    fatoora_string_free(hash.value);
    fatoora_string_free(qr.value);
    free(xml_cstr);
    fatoora_signed_invoice_free(&signed_invoice.value);
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
