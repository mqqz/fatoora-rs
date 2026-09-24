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
    DiplomatWrite *out = diplomat_buffer_write_create(0);
    fatoora_SignedInvoice_qr_code_result qr = fatoora_SignedInvoice_qr_code(invoice.ok, out);
    assert(qr.is_ok && diplomat_buffer_write_len(out) > 0);
    fatoora_SignedInvoice_destroy(invoice.ok);
    fwrite(diplomat_buffer_write_get_bytes(out), 1, diplomat_buffer_write_len(out), stdout);
    diplomat_buffer_write_destroy(out);
    return 0;
}
/* --8<-- [end:example] */
