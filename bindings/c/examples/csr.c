/* --8<-- [start:example] */
#include "BindingError.h"
#include "Csr.h"
#include "CsrProperties.h"
#include "SigningKey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FATOORA_DOC_CSR_PROPS
#define FATOORA_DOC_CSR_PROPS "path/to/csr.properties"
#endif

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

int main(void) {
  int status = EXIT_FAILURE;
  CsrProperties *properties = NULL;
  SigningKey *key = NULL;
  Csr *csr = NULL;
  DiplomatWrite *pem = NULL;

  fatoora_CsrProperties_parse_csr_config_file_result parsed =
      fatoora_CsrProperties_parse_csr_config_file(s(FATOORA_DOC_CSR_PROPS));
  if (!parsed.is_ok) { report_error(parsed.err); goto cleanup; }
  properties = parsed.ok;

  fatoora_SigningKey_generate_result generated = fatoora_SigningKey_generate();
  if (!generated.is_ok) { report_error(generated.err); goto cleanup; }
  key = generated.ok;

  /* Environment 0 selects the non-production CSR template. */
  fatoora_CsrProperties_build_result built =
      fatoora_CsrProperties_build(properties, key, 0);
  if (!built.is_ok) { report_error(built.err); goto cleanup; }
  csr = built.ok;

  pem = diplomat_buffer_write_create(0);
  fatoora_Csr_to_pem_result encoded = fatoora_Csr_to_pem(csr, pem);
  if (!encoded.is_ok) { report_error(encoded.err); goto cleanup; }
  size_t length = diplomat_buffer_write_len(pem);
  if (fwrite(diplomat_buffer_write_get_bytes(pem), 1, length, stdout) != length) {
    fputs("Failed to write CSR PEM.\n", stderr);
    goto cleanup;
  }
  status = EXIT_SUCCESS;

cleanup:
  if (pem) diplomat_buffer_write_destroy(pem);
  if (csr) fatoora_Csr_destroy(csr);
  if (key) fatoora_SigningKey_destroy(key);
  if (properties) fatoora_CsrProperties_destroy(properties);
  return status;
}
/* --8<-- [end:example] */
