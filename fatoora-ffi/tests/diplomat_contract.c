#include "Address.h"
#include "BindingError.h"
#include "Config.h"
#include "FinalizedInvoice.h"
#include "InvoiceBuilder.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static DiplomatStringView s(const char *v) {
    return (DiplomatStringView){v, strlen(v)};
}
static OptionStringView none(void) {
    return (OptionStringView){.is_ok = false};
}
static OptionStringView some(const char *v) {
    return (OptionStringView){.ok = {v, strlen(v)}, .is_ok = true};
}
static void invalid_input(BindingError *error) {
    assert(fatoora_BindingError_code(error) == 1);
    fatoora_BindingError_destroy(error);
}
#define INVALID(type, expression) do { \
    type result = (expression); \
    assert(!result.is_ok); \
    invalid_input(result.err); \
} while (0)

static InvoiceBuilder *builder(void) {
    fatoora_InvoiceBuilder_new_result result = fatoora_InvoiceBuilder_new(
        0, 1, none(), none(), none(), none());
    assert(result.is_ok);
    InvoiceBuilder *b = result.ok;
    assert(fatoora_InvoiceBuilder_set_id(b, s("INV-1")).is_ok);
    assert(fatoora_InvoiceBuilder_set_uuid(b, s("8e6000cf-1a98-4174-b3e7-b5d5954bc10d")).is_ok);
    assert(fatoora_InvoiceBuilder_set_issue_datetime(b, s("2024-01-01T12:30:00Z")).is_ok);
    assert(fatoora_InvoiceBuilder_set_currency(b, s("SAR")).is_ok);
    assert(fatoora_InvoiceBuilder_set_previous_invoice_hash(b, s("hash")).is_ok);
    assert(fatoora_InvoiceBuilder_set_invoice_counter(b, 1).is_ok);
    assert(fatoora_InvoiceBuilder_set_payment_means_code(b, s("10")).is_ok);
    assert(fatoora_InvoiceBuilder_set_vat_category(b, 1).is_ok);
    fatoora_Address_new_result address = fatoora_Address_new(
        s("SA"), s("Riyadh"), s("King Fahd"), s("1234"), s("12222"),
        none(), none(), some("Olaya"));
    assert(address.is_ok);
    assert(fatoora_InvoiceBuilder_set_seller(b, s("Seller"), address.ok,
        s("399999999900003"), some("7003339333"), some("CRN")).is_ok);
    /* Setter copies the address; destroying its owner must be safe. */
    fatoora_Address_destroy(address.ok);
    return b;
}

int main(void) {
    INVALID(fatoora_Config_new_result, fatoora_Config_new(255));
    INVALID(fatoora_InvoiceBuilder_new_result,
        fatoora_InvoiceBuilder_new(255, 1, none(), none(), none(), none()));
    INVALID(fatoora_InvoiceBuilder_new_result,
        fatoora_InvoiceBuilder_new(0, 255, none(), none(), none(), none()));
    InvoiceBuilder *b = builder();
    INVALID(fatoora_InvoiceBuilder_set_vat_category_result,
        fatoora_InvoiceBuilder_set_vat_category(b, 255));
    const char bad_utf8[] = {(char)0xff};
    const char nul_text[] = {'a', 0, 'b'};
    INVALID(fatoora_InvoiceBuilder_add_line_item_result,
        fatoora_InvoiceBuilder_add_line_item(b,
            ((DiplomatStringView){bad_utf8, sizeof(bad_utf8)}),
            s("3"), s("PCE"), s("1"), s("15"), 1));
    INVALID(fatoora_InvoiceBuilder_add_line_item_result,
        fatoora_InvoiceBuilder_add_line_item(b,
            ((DiplomatStringView){nul_text, sizeof(nul_text)}),
            s("3"), s("PCE"), s("1"), s("15"), 1));
    INVALID(fatoora_InvoiceBuilder_add_line_item_result,
        fatoora_InvoiceBuilder_add_line_item(b, s("Item"), s("3"), s("PCE"), s("1"), s("15"), 255));
    fatoora_InvoiceBuilder_add_line_item_result bad = fatoora_InvoiceBuilder_add_line_item(
        b, s("Item"), s("3"), s("PCE"), s("invalid"), s("15"), 1);
    assert(!bad.is_ok && fatoora_BindingError_code(bad.err) == 1);
    char details[4096] = {0};
    DiplomatWrite detail_out = diplomat_simple_write(details, sizeof(details));
    fatoora_BindingError_details_json(bad.err, &detail_out);
    fatoora_BindingError_destroy(bad.err);
    assert(strstr(details, "invalid_decimal"));
    assert(fatoora_InvoiceBuilder_add_line_item(
        b, s("Item"), s("3"), s("PCE"), s("0.3333"), s("15"), 1).is_ok);
    fatoora_InvoiceBuilder_build_result built = fatoora_InvoiceBuilder_build(b);
    assert(built.is_ok);
    DiplomatWrite *out = diplomat_buffer_write_create(0);
    assert(fatoora_FinalizedInvoice_xml(built.ok, out).is_ok);
    size_t len = diplomat_buffer_write_len(out);
    char *xml = malloc(len + 1);
    assert(xml);
    memcpy(xml, diplomat_buffer_write_get_bytes(out), len);
    xml[len] = '\0';
    diplomat_buffer_write_destroy(out);
    fatoora_FinalizedInvoice_destroy(built.ok);
    assert(strstr(xml, ">0.3333</cbc:PriceAmount>"));
    assert(strstr(xml, ">1.15</cbc:TaxInclusiveAmount>"));
    free(xml);
    INVALID(fatoora_InvoiceBuilder_build_result, fatoora_InvoiceBuilder_build(b));
    INVALID(fatoora_InvoiceBuilder_set_id_result, fatoora_InvoiceBuilder_set_id(b, s("again")));
    fatoora_InvoiceBuilder_destroy(b);
    b = builder();
    fatoora_InvoiceBuilder_build_result failed = fatoora_InvoiceBuilder_build(b);
    assert(!failed.is_ok);
    fatoora_BindingError_destroy(failed.err);
    INVALID(fatoora_InvoiceBuilder_build_result, fatoora_InvoiceBuilder_build(b));
    fatoora_InvoiceBuilder_destroy(b);
    return 0;
}
