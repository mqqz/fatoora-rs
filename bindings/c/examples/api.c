/* --8<-- [start:example] */
#include "BindingError.h"
#include "Config.h"
#include "CsidProduction.h"
#include "SignedInvoice.h"
#include "ValidationResponse.h"
#include "ZatcaClient.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static DiplomatStringView s(const char *value) {
  return (DiplomatStringView){value, strlen(value)};
}

static void report_error(BindingError *error) {
  DiplomatWrite *output = diplomat_buffer_write_create(0);
  fatoora_BindingError_details_json(error, output);
  fwrite(diplomat_buffer_write_get_bytes(output), 1,
         diplomat_buffer_write_len(output), stderr);
  fputc('\n', stderr);
  diplomat_buffer_write_destroy(output);
  fatoora_BindingError_destroy(error);
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(argc == 1 ? stdout : stderr,
            "Usage: %s signed-invoice.xml token secret\n"
            "Submits a simplified invoice to the non-production gateway.\n",
            argv[0]);
    return argc == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  int status = EXIT_FAILURE;
  Config *config = NULL;
  SignedInvoice *invoice = NULL;
  CsidProduction *credentials = NULL;
  ZatcaClient *client = NULL;
  ValidationResponse *response = NULL;

  fatoora_SignedInvoice_from_file_result parsed =
      fatoora_SignedInvoice_from_file(s(argv[1]));
  if (!parsed.is_ok) { report_error(parsed.err); goto cleanup; }
  invoice = parsed.ok;

  /* Environment 0 is the ZATCA integration sandbox. */
  fatoora_Config_new_result configured = fatoora_Config_new(0);
  if (!configured.is_ok) { report_error(configured.err); goto cleanup; }
  config = configured.ok;
  fatoora_ZatcaClient_create_result created = fatoora_ZatcaClient_create(config);
  if (!created.is_ok) { report_error(created.err); goto cleanup; }
  client = created.ok;

  OptionStringView no_request_id = {.is_ok = false};
  fatoora_CsidProduction_create_result authenticated =
      fatoora_CsidProduction_create(0, no_request_id, s(argv[2]), s(argv[3]));
  if (!authenticated.is_ok) { report_error(authenticated.err); goto cleanup; }
  credentials = authenticated.ok;

  OptionStringView language = {.ok = s("en"), .is_ok = true};
  fatoora_ZatcaClient_report_simplified_invoice_result reported =
      fatoora_ZatcaClient_report_simplified_invoice(
          client, invoice, credentials, false, language);
  if (!reported.is_ok) { report_error(reported.err); goto cleanup; }
  response = reported.ok;

  /* A decoded HTTP response does not by itself establish acceptance. */
  fatoora_ValidationResponse_ensure_accepted_result accepted =
      fatoora_ValidationResponse_ensure_accepted(response);
  if (!accepted.is_ok) { report_error(accepted.err); goto cleanup; }
  puts("Invoice reporting accepted.");
  status = EXIT_SUCCESS;

cleanup:
  if (response) fatoora_ValidationResponse_destroy(response);
  if (client) fatoora_ZatcaClient_destroy(client);
  if (credentials) fatoora_CsidProduction_destroy(credentials);
  if (invoice) fatoora_SignedInvoice_destroy(invoice);
  if (config) fatoora_Config_destroy(config);
  return status;
}
/* --8<-- [end:example] */
