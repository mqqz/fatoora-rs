/* Compile as C and C++; argv[1] is the standard invoice SDK fixture. */
#include "fatoora.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_invoice(const char *path) {
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) == 0);
    long size = ftell(file);
    assert(size > 0 && size < 1000000);
    rewind(file);
    char *xml = (char *)malloc((size_t)size + 1);
    assert(xml != NULL);
    assert(fread(xml, 1, (size_t)size, file) == (size_t)size);
    xml[size] = '\0';
    fclose(file);
    return xml;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    char *xml = read_invoice(argv[1]);
    struct FfiConfig *config = fatoora_config_new(FfiEnvironment_NonProduction);
    const char *options = "{\"previous_invoice_hash\":\"NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==\",\"evaluated_at\":\"2026-09-23T12:00:00+03:00\"}";
    struct FfiResult_FfiString good = fatoora_validate_zatca_invoice_from_str(config, xml, options);
    assert(good.ok && good.error == NULL);
    assert(strstr(good.value.ptr, "\"is_valid\":true"));
    assert(strstr(good.value.ptr, "\"severity\":\"warning\""));
    struct FfiResult_FfiString missing = fatoora_validate_zatca_invoice_from_str(config, xml, NULL);
    assert(missing.ok && strstr(missing.value.ptr, "context_required"));
    assert(strstr(missing.value.ptr, "\"is_valid\":false"));
    fatoora_string_free(missing.value);
    struct FfiResult_FfiString rejected = fatoora_validate_zatca_invoice_from_str(config, "<wrong/>", options);
    assert(rejected.ok && strstr(rejected.value.ptr, "XSD_INVALID"));
    fatoora_string_free(rejected.value);
    struct FfiResult_FfiString bad = fatoora_validate_zatca_invoice_from_str(config, "<Invoice", options);
    assert(!bad.ok && fatoora_error_code(bad.error) == 4);
    struct FfiString details = fatoora_error_details_json(bad.error);
    fatoora_error_free(bad.error);
    assert(strstr(details.ptr, "zatca_validation_execution"));
    assert(strstr(details.ptr, "\"report\":"));
    struct FfiResult_FfiString unknown = fatoora_validate_zatca_invoice_from_str(config, xml, "{\"unknown\":true}");
    assert(!unknown.ok && fatoora_error_code(unknown.error) == 1);
    fatoora_error_free(unknown.error);
    struct FfiResult_FfiString null_xml = fatoora_validate_zatca_invoice_from_str(config, NULL, NULL);
    assert(!null_xml.ok);
    fatoora_error_free(null_xml.error);
    struct FfiResult_FfiString utf8 = fatoora_validate_zatca_invoice_from_str(config, "\xff", NULL);
    assert(!utf8.ok);
    fatoora_error_free(utf8.error);
    char oversized_options[4098];
    memset(oversized_options, ' ', sizeof(oversized_options));
    oversized_options[0] = '{';
    oversized_options[4096] = '}';
    oversized_options[4097] = '\0';
    struct FfiResult_FfiString capacity = fatoora_validate_zatca_invoice_from_str(config, xml, oversized_options);
    assert(!capacity.ok && fatoora_error_code(capacity.error) == 1);
    fatoora_error_free(capacity.error);
    fatoora_config_free(config);
    free(xml);
    assert(strstr(good.value.ptr, "\"is_complete\":true"));
    assert(strstr(details.ptr, "invalid_xml"));
    fatoora_string_free(good.value);
    fatoora_string_free(details);
    puts("ZATCA C report ownership and execution contracts passed");
    return 0;
}
