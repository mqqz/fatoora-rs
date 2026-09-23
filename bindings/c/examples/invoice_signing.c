/* --8<-- [start:example] */
#include "SignedInvoice.h"
#include "BindingError.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifndef FATOORA_DOC_SIGNED_XML
#define FATOORA_DOC_SIGNED_XML "path/to/signed_invoice.xml"
#endif
static DiplomatStringView s(const char *v) { return (DiplomatStringView){v,strlen(v)}; }
int main(void) {
    fatoora_SignedInvoice_from_file_result invoice = fatoora_SignedInvoice_from_file(s(FATOORA_DOC_SIGNED_XML));
    assert(invoice.is_ok);
    DiplomatWrite *copy = diplomat_buffer_write_create(0);
    fatoora_SignedInvoice_xml_result copied = fatoora_SignedInvoice_xml(invoice.ok, copy);
    assert(copied.is_ok);
    DiplomatWrite *owned = diplomat_buffer_write_create(0);
    fatoora_SignedInvoice_into_xml_result taken = fatoora_SignedInvoice_into_xml(invoice.ok, owned);
    assert(taken.is_ok);
    fatoora_SignedInvoice_xml_result consumed = fatoora_SignedInvoice_xml(invoice.ok, copy);
    assert(!consumed.is_ok && fatoora_BindingError_code(consumed.err) == 1);
    fatoora_BindingError_destroy(consumed.err);
    fatoora_SignedInvoice_destroy(invoice.ok);
    assert(diplomat_buffer_write_len(copy) == diplomat_buffer_write_len(owned));
    assert(memcmp(diplomat_buffer_write_get_bytes(copy), diplomat_buffer_write_get_bytes(owned), diplomat_buffer_write_len(copy)) == 0);
    diplomat_buffer_write_destroy(copy);
    diplomat_buffer_write_destroy(owned);
    return 0;
}
/* --8<-- [end:example] */
