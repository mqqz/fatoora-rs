#include "fatoora.h"
#include <stdio.h>

static int write_pem(const char *path, const char *pem) {
    FILE *file = fopen(path, "wb");
    if (!file) return 0;
    int written = fputs(pem, file) >= 0;
    return fclose(file) == 0 && written;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s csr.properties\n", argv[0]);
        return 1;
    }
    FatooraCsrProperties *properties = NULL;
    FatooraSigningKey *key = NULL;
    FatooraCsr *csr = NULL;
    FatooraError *error = NULL;
    char *csr_pem = NULL, *key_pem = NULL;
    FatooraStatus status = FATOORA_OK;
    int exit_code = 1;
#define TRY(call) do { status = (call); if (status != FATOORA_OK) goto cleanup; } while (0)
    TRY(fatoora_csr_properties_parse_csr_config_file(argv[1], &properties, &error));
    TRY(fatoora_signing_key_generate(&key, &error));
    TRY(fatoora_csr_properties_build(properties, key, FATOORA_NON_PRODUCTION, &csr, &error));
    TRY(fatoora_csr_to_pem(csr, &csr_pem, &error));
    TRY(fatoora_signing_key_to_pem(key, &key_pem, &error));
    if (!write_pem("key.pem", key_pem) || !write_pem("csr.pem", csr_pem)) {
        fputs("Unable to write key.pem or csr.pem.\n", stderr);
        goto cleanup;
    }
    puts("Saved csr.pem and key.pem");
    exit_code = 0;
cleanup:
    if (status != FATOORA_OK) fprintf(stderr, "Error %d: %s\n", (int)status, fatoora_error_message(error));
    fatoora_string_free(key_pem);
    fatoora_string_free(csr_pem);
    fatoora_csr_free(csr);
    fatoora_signing_key_free(key);
    fatoora_csr_properties_free(properties);
    fatoora_error_free(error);
    return exit_code;
}
