/* --8<-- [start:example] */
#include "fatoora.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef FATOORA_DOC_INVOICE_XML
#define FATOORA_DOC_INVOICE_XML "path/to/invoice.xml"
#endif

static char *read_file(const char *path);

int main(void) {
  const char *invoice_xml_path = FATOORA_DOC_INVOICE_XML;
  char *xml_cstr = read_file(invoice_xml_path);
  struct FfiConfig *config = fatoora_config_new(FfiEnvironment_NonProduction);

  /* invoice_xml_path = "path/to/invoice.xml" */
  struct FfiResult_bool result =
      fatoora_validate_xml_invoice_from_str(config, xml_cstr);

  assert(result.value);

  // you know the drill by now
  free(xml_cstr);
  fatoora_config_free(config);
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
