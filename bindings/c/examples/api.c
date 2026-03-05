const char *EXAMPLE_BST =
    "TUlJRDNqQ0NBNFNnQXdJQkFnSVRFUUFBT0FQRjkwQWpzL3hjWHdBQkFBQTRBekFLQmdncWhrak"
    "9QUVFEQWpCaU1SVXdFd1lLQ1pJbWlaUHlMR1FCR1JZRmJHOWpZV3d4RXpBUkJnb0praWFKay9J"
    "c1pBRVpGZ05uYjNZeEZ6QVZCZ29Ka2lhSmsvSXNaQUVaRmdkbGVIUm5ZWHAwTVJzd0dRWURWUV"
    "FERXhKUVVscEZTVTVXVDBsRFJWTkRRVFF0UTBFd0hoY05NalF3TVRFeE1Ea3hPVE13V2hjTk1q"
    "a3dNVEE1TURreE9UTXdXakIxTVFzd0NRWURWUVFHRXdKVFFURW1NQ1FHQTFVRUNoTWRUV0Y0YV"
    "cxMWJTQlRjR1ZsWkNCVVpXTm9JRk4xY0hCc2VTQk1WRVF4RmpBVUJnTlZCQXNURFZKcGVXRmth"
    "Q0JDY21GdVkyZ3hKakFrQmdOVkJBTVRIVlJUVkMwNE9EWTBNekV4TkRVdE16azVPVGs1T1RrNU"
    "9UQXdNREF6TUZZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUFvRFFnQUVvV0NLYTBTYTlGSUVyVE92"
    "MHVBa0MxVklLWHhVOW5QcHgydmxmNHloTWVqeThjMDJYSmJsRHE3dFB5ZG84bXEwYWhPTW1Obz"
    "hnd25pN1h0MUtUOVVlS09DQWdjd2dnSURNSUd0QmdOVkhSRUVnYVV3Z2FLa2daOHdnWnd4T3pB"
    "NUJnTlZCQVFNTWpFdFZGTlVmREl0VkZOVWZETXRaV1F5TW1ZeFpEZ3RaVFpoTWkweE1URTRMVG"
    "xpTlRndFpEbGhPR1l4TVdVME5EVm1NUjh3SFFZS0NaSW1pWlB5TEdRQkFRd1BNems1T1RrNU9U"
    "azVPVEF3TURBek1RMHdDd1lEVlFRTURBUXhNVEF3TVJFd0R3WURWUVFhREFoU1VsSkVNamt5T1"
    "RFYU1CZ0dBMVVFRHd3UlUzVndjR3g1SUdGamRHbDJhWFJwWlhNd0hRWURWUjBPQkJZRUZFWCtZ"
    "dm1tdG5Zb0RmOUJHYktvN29jVEtZSzFNQjhHQTFVZEl3UVlNQmFBRkp2S3FxTHRtcXdza0lGel"
    "Z2cFAyUHhUKzlObk1Ic0dDQ3NHQVFVRkJ3RUJCRzh3YlRCckJnZ3JCZ0VGQlFjd0FvWmZhSFIw"
    "Y0RvdkwyRnBZVFF1ZW1GMFkyRXVaMjkyTG5OaEwwTmxjblJGYm5KdmJHd3ZVRkphUlVsdWRtOX"
    "BZMlZUUTBFMExtVjRkR2RoZW5RdVoyOTJMbXh2WTJGc1gxQlNXa1ZKVGxaUFNVTkZVME5CTkMx"
    "RFFTZ3hLUzVqY25Rd0RnWURWUjBQQVFIL0JBUURBZ2VBTUR3R0NTc0dBUVFCZ2pjVkJ3UXZNQz"
    "BHSlNzR0FRUUJnamNWQ0lHR3FCMkUwUHNTaHUyZEpJZk8reG5Ud0ZWbWgvcWxaWVhaaEQ0Q0FX"
    "UUNBUkl3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdNR0NDc0dBUVVGQndNQ01DY0dDU3NHQV"
    "FRQmdqY1ZDZ1FhTUJnd0NnWUlLd1lCQlFVSEF3TXdDZ1lJS3dZQkJRVUhBd0l3Q2dZSUtvWkl6"
    "ajBFQXdJRFNBQXdSUUloQUxFL2ljaG1uV1hDVUtVYmNhM3ljaThvcXdhTHZGZEhWalFydmVJOX"
    "VxQWJBaUE5aEM0TThqZ01CQURQU3ptZDJ1aVBKQTZnS1IzTEUwM1U3NWVxYkMvclhBPT0=";

const char *EXAMPLE_SECRET = "CkYsEXfV8c1gFHAtFWoZv73pGMvh/Qyo4LzKM2h/8Hg=";

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
  // parse the signed XML invoice into a struct
  const char *signed_xml_path = FATOORA_DOC_SIGNED_XML;
  char *xml_cstr = read_file(signed_xml_path);
  struct FfiResult_FfiSignedInvoice signed_invoice =
      fatoora_parse_signed_invoice_xml(xml_cstr);

  struct FfiConfig *config = fatoora_config_new(FfiEnvironment_NonProduction);
  struct FfiResult_FfiZatcaClient client = fatoora_zatca_client_new(config);

  struct FfiResult_FfiCsidProduction pcsid = fatoora_csid_production_new(
      FfiEnvironment_NonProduction, NULL, EXAMPLE_BST, EXAMPLE_SECRET);

  // response handle provides getters for results
  FfiResult_FfiValidationResponse resp =
      fatoora_zatca_report_simplified_invoice(
          &client.value, &signed_invoice.value, &pcsid.value, true, "en");

  FfiResult_FfiString reporting_status =
      fatoora_validation_response_reporting_status(&resp.value);

  assert(!strcmp(reporting_status.value.ptr, "REPORTED"));

  // don't forget to free all the resources you allocated!
  free(xml_cstr);
  fatoora_signed_invoice_free(&signed_invoice.value);
  fatoora_csid_production_free(&pcsid.value);
  fatoora_validation_response_free(&resp.value);
  fatoora_zatca_client_free(&client.value);
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
