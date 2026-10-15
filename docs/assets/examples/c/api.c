#include "fatoora.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(argc == 1 ? stdout : stderr,
            "Usage: %s signed-invoice.xml\n"
            "Submits a simplified invoice to the non-production gateway.\n", argv[0]);
        return argc == 1 ? 0 : 1;
    }
    const char *token = getenv("ZATCA_TOKEN"), *secret = getenv("ZATCA_SECRET");
    if (!token || !secret) { fputs("Set ZATCA_TOKEN and ZATCA_SECRET first.\n", stderr); return 1; }
    FatooraConfig *config = NULL;
    FatooraSignedInvoice *invoice = NULL;
    FatooraCsidProduction *credentials = NULL;
    FatooraZatcaClient *client = NULL;
    FatooraValidationResponse *response = NULL;
    FatooraError *error = NULL;
    FatooraStatus status = FATOORA_OK;
    int exit_code = 1;
#define TRY(call) do { status = (call); if (status != FATOORA_OK) goto cleanup; } while (0)
    TRY(fatoora_signed_invoice_from_file(argv[1], &invoice, &error));
    TRY(fatoora_config_new(FATOORA_NON_PRODUCTION, &config, &error));
    TRY(fatoora_zatca_client_create(config, &client, &error));
    TRY(fatoora_csid_production_create(FATOORA_NON_PRODUCTION, NULL,
        token, secret, &credentials, &error));
    TRY(fatoora_zatca_client_report_simplified_invoice(client, invoice,
        credentials, false, "en", &response, &error));
    /* Receiving a response does not establish acceptance. */
    TRY(fatoora_validation_response_ensure_accepted(response, &error));
    puts("Invoice reporting accepted.");
    exit_code = 0;
cleanup:
    if (exit_code) fprintf(stderr, "Error %d: %s\n%s\n", (int)status,
        fatoora_error_message(error), fatoora_error_details_json(error));
    fatoora_validation_response_free(response);
    fatoora_zatca_client_free(client);
    fatoora_csid_production_free(credentials);
    fatoora_signed_invoice_free(invoice);
    fatoora_config_free(config);
    fatoora_error_free(error);
    return exit_code;
}
