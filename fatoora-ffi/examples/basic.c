#include "FinalizedInvoice.h"
#include "BindingError.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) { puts("Usage: basic invoice.xml"); return 0; }
    DiplomatStringView path = {argv[1], strlen(argv[1])};
    fatoora_FinalizedInvoice_from_file_result invoice = fatoora_FinalizedInvoice_from_file(path);
    DiplomatWrite *out = diplomat_buffer_write_create(0);
    if (!invoice.is_ok) {
        fatoora_BindingError_message(invoice.err, out);
        fwrite(diplomat_buffer_write_get_bytes(out), 1, diplomat_buffer_write_len(out), stderr);
        fatoora_BindingError_destroy(invoice.err);
        diplomat_buffer_write_destroy(out);
        return 1;
    }
    fatoora_FinalizedInvoice_xml_result xml = fatoora_FinalizedInvoice_xml(invoice.ok, out);
    if (!xml.is_ok) { fatoora_BindingError_destroy(xml.err); }
    else { fwrite(diplomat_buffer_write_get_bytes(out), 1, diplomat_buffer_write_len(out), stdout); }
    fatoora_FinalizedInvoice_destroy(invoice.ok);
    diplomat_buffer_write_destroy(out);
    return xml.is_ok ? 0 : 1;
}
