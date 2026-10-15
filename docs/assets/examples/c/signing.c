#include "fatoora.h"
#include <stdio.h>
#include <stdlib.h>

/* Read a PEM file into a NUL-terminated string. */
static char *read_pem(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    char *data = NULL;
    if (fseek(file, 0, SEEK_END)) goto done;
    long size = ftell(file);
    if (size <= 0 || size > 1024 * 1024) goto done;
    rewind(file);
    data = malloc((size_t)size + 1);
    if (!data) goto done;
    if (fread(data, 1, (size_t)size, file) != (size_t)size) {
        free(data);
        data = NULL;
    } else {
        data[size] = '\0';
    }
done:
    fclose(file);
    return data;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s invoice.xml certificate.pem private-key.pem\n", argv[0]);
        return 1;
    }
    char *cert = read_pem(argv[2]);
    char *key = read_pem(argv[3]);
    if (!cert || !key) {
        fputs("Unable to read certificate or private key PEM.\n", stderr);
        free(cert);
        free(key);
        return 1;
    }
    FatooraSigner *signer = NULL;
    FatooraFinalizedInvoice *invoice = NULL;
    FatooraSignedInvoice *signed_invoice = NULL;
    FatooraError *error = NULL;
    char *xml = NULL;
    FatooraStatus status = FATOORA_OK;
    int exit_code = 1;
#define TRY(call) do { status = (call); if (status != FATOORA_OK) goto cleanup; } while (0)
    TRY(fatoora_signer_from_pem(cert, key, &signer, &error));
    TRY(fatoora_finalized_invoice_from_file(argv[1], &invoice, &error));
    /* Signing consumes invoice's inner state; its outer handle still needs free. */
    TRY(fatoora_signer_sign(signer, invoice, &signed_invoice, &error));
    TRY(fatoora_signed_invoice_into_xml(signed_invoice, &xml, &error));
    puts(xml);
    exit_code = 0;
cleanup:
    if (exit_code) fprintf(stderr, "Error %d: %s\n", (int)status, fatoora_error_message(error));
    fatoora_string_free(xml);
    fatoora_signed_invoice_free(signed_invoice);
    fatoora_finalized_invoice_free(invoice);
    fatoora_signer_free(signer);
    fatoora_error_free(error);
    free(cert);
    free(key);
    return exit_code;
}
