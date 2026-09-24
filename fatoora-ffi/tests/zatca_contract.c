/* Compile as C and C++; argv[1] is the standard invoice SDK fixture. */
#include "Config.h"
#include "Xml.h"
#include "BindingError.h"
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

static DiplomatStringView view(const char *text) {
    DiplomatStringView value = {text, strlen(text)};
    return value;
}

static DiplomatWrite *report(const Config *config, const char *xml, const char *options) {
    DiplomatWrite *out = diplomat_buffer_write_create(0);
    OptionStringView opts = {0};
    if (options != NULL) { opts.is_ok = true; opts.ok = view(options); }
    fatoora_Xml_validate_zatca_result result = fatoora_Xml_validate_zatca(config, view(xml), opts, out);
    assert(result.is_ok);
    return out;
}

static void invalid(const Config *config, DiplomatStringView xml, const char *options) {
    DiplomatWrite *out = diplomat_buffer_write_create(0);
    OptionStringView opts = {0};
    if (options != NULL) { opts.is_ok = true; opts.ok = view(options); }
    fatoora_Xml_validate_zatca_result result = fatoora_Xml_validate_zatca(config, xml, opts, out);
    assert(!result.is_ok && fatoora_BindingError_code(result.err) == 1);
    fatoora_BindingError_destroy(result.err);
    diplomat_buffer_write_destroy(out);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    char *xml = read_invoice(argv[1]);
    fatoora_Config_new_result created = fatoora_Config_new(0);
    assert(created.is_ok);
    Config *config = created.ok;
    const char *options = "{\"previous_invoice_hash\":\"NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==\",\"evaluated_at\":\"2026-09-23T12:00:00+03:00\"}";
    DiplomatWrite *good = report(config, xml, options);
    assert(strstr(diplomat_buffer_write_get_bytes(good), "\"is_valid\":true"));
    assert(strstr(diplomat_buffer_write_get_bytes(good), "\"severity\":\"warning\""));
    DiplomatWrite *missing = report(config, xml, NULL);
    assert(strstr(diplomat_buffer_write_get_bytes(missing), "context_required"));
    assert(strstr(diplomat_buffer_write_get_bytes(missing), "\"is_valid\":false"));
    diplomat_buffer_write_destroy(missing);
    DiplomatWrite *rejected = report(config, "<wrong/>", options);
    assert(strstr(diplomat_buffer_write_get_bytes(rejected), "XSD_INVALID"));
    diplomat_buffer_write_destroy(rejected);
    DiplomatWrite *out = diplomat_buffer_write_create(0);
    OptionStringView defaults = {0};
    fatoora_Xml_validate_zatca_result bad = fatoora_Xml_validate_zatca(config, view("<Invoice"), defaults, out);
    assert(!bad.is_ok && fatoora_BindingError_code(bad.err) == 4);
    DiplomatWrite *details = diplomat_buffer_write_create(0);
    fatoora_BindingError_details_json(bad.err, details);
    fatoora_BindingError_destroy(bad.err);
    diplomat_buffer_write_destroy(out);
    assert(strstr(diplomat_buffer_write_get_bytes(details), "zatca_validation_execution"));
    assert(strstr(diplomat_buffer_write_get_bytes(details), "\"report\":"));
    invalid(config, view(xml), "{\"unknown\":true}");
    invalid(config, view("\xff"), NULL);
    DiplomatStringView nul = {"<x/>\0ignored", 12};
    invalid(config, nul, NULL);
    char oversized_options[4098];
    memset(oversized_options, ' ', sizeof(oversized_options));
    oversized_options[4097] = '\0';
    invalid(config, view(xml), oversized_options);
    fatoora_Config_destroy(config);
    free(xml);
    assert(strstr(diplomat_buffer_write_get_bytes(good), "\"is_complete\":true"));
    assert(strstr(diplomat_buffer_write_get_bytes(details), "invalid_xml"));
    diplomat_buffer_write_destroy(good);
    diplomat_buffer_write_destroy(details);
    puts("ZATCA C report ownership and execution contracts passed");
    return 0;
}
