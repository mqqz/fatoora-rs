#include "fatoora.h"
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s signed-invoice.xml\n", argv[0]);
        return 1;
    }
    FatooraSignedInvoice *invoice = NULL;
    FatooraError *error = NULL;
    char *qr = NULL;
    FatooraStatus status = fatoora_signed_invoice_from_file(argv[1], &invoice, &error);
    if (status == FATOORA_OK)
        status = fatoora_signed_invoice_qr_code(invoice, &qr, &error);
    if (status == FATOORA_OK) puts(qr);
    else fprintf(stderr, "Error %d: %s\n", (int)status, fatoora_error_message(error));
    fatoora_string_free(qr);
    fatoora_signed_invoice_free(invoice);
    fatoora_error_free(error);
    return status == FATOORA_OK ? 0 : 1;
}
