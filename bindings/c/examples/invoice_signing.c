/* --8<-- [start:example] */
#include "fatoora.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FATOORA_DOC_SIGNED_XML
#define FATOORA_DOC_SIGNED_XML "path/to/signed_invoice.xml"
#endif

static char *read_file(const char *path);

int main(void) {
  const char *signed_xml_path = FATOORA_DOC_SIGNED_XML;
  char *xml_cstr = read_file(signed_xml_path);

  /* signed_xml_path = "path/to/signed_invoice.xml" */
  struct FfiResult_FfiSignedInvoice signed_invoice =
      fatoora_parse_signed_invoice_xml(xml_cstr);
  assert(signed_invoice.ok);

  struct FfiResult_FfiString hash =
      fatoora_signed_invoice_hash(&signed_invoice.value);

  assert(hash.ok);
  assert(strcmp(hash.value.ptr, "z5F9qsS6oWyDhehD8u8S0DaxV+2CUiUz9Y+UsR61JgQ=") == 0);

  /* Copying leaves the invoice available for further access. */
  struct FfiResult_FfiString copied =
      fatoora_signed_invoice_to_xml(&signed_invoice.value);
  assert(copied.ok);
  assert(signed_invoice.value.ptr != NULL);

  /* Taking the XML consumes the invoice and clears its handle. */
  struct FfiResult_FfiString owned =
      fatoora_signed_invoice_into_xml(&signed_invoice.value);
  assert(owned.ok);
  assert(signed_invoice.value.ptr == NULL);
  assert(strcmp(copied.value.ptr, xml_cstr) == 0);
  assert(strcmp(owned.value.ptr, xml_cstr) == 0);
  fatoora_string_free(copied.value);
  fatoora_string_free(owned.value);

  // Again don't forget to free
  fatoora_string_free(hash.value);
  free(xml_cstr);
  fatoora_signed_invoice_free(&signed_invoice.value);
  return 0;
}
/* --8<-- [end:example] */

static char *read_file(const char *path) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return NULL;
  }
  long size = ftell(fp);
  if (size < 0) {
    fclose(fp);
    return NULL;
  }
  rewind(fp);
  char *buffer = malloc((size_t)size + 1);
  if (!buffer) {
    fclose(fp);
    return NULL;
  }
  if (fread(buffer, 1, (size_t)size, fp) != (size_t)size) {
    fclose(fp);
    free(buffer);
    return NULL;
  }
  buffer[size] = '\0';
  fclose(fp);
  return buffer;
}
