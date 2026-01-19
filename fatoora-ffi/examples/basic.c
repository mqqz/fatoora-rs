#include <stdio.h>
#include <stdint.h>

#define FATOORA_FFI_NO_PREFIX
#include "fatoora.h"

int main(void) {
    InvoiceBuilder builder = {0};
    FinalizedInvoice invoice = {0};
    SignedInvoice signed_invoice = {0};
    Signer signer = {0};
    FfiResult_FfiInvoiceBuilder builder_result;
    FfiResult_FfiFinalizedInvoice invoice_result;
    FfiResult_FfiSignedInvoice signed_result;
    FfiResult_FfiString xml_result;

    builder_result = fatoora_invoice_builder_new(
        InvoiceTypeKind_Tax,
        InvoiceSubType_Simplified,
        "INV-1",
        "123e4567-e89b-12d3-a456-426614174000",
        1700000000,
        0,
        "SAR",
        "hash",
        1,
        "10",
        VatCategory_Standard,
        "Acme Inc",
        "SAU",
        "Riyadh",
        "King Fahd",
        NULL,
        "1234",
        NULL,
        "12222",
        NULL,
        NULL,
        "399999999900003",
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (!builder_result.ok) {
        fprintf(stderr, "builder error: %s\n", builder_result.error);
        fatoora_error_free(builder_result.error);
        return 1;
    }

    builder = builder_result.value;
    fatoora_invoice_builder_add_line_item(
        &builder,
        "Item",
        1.0,
        "PCE",
        100.0,
        15.0,
        VatCategory_Standard
    );

    invoice_result = fatoora_invoice_builder_build(&builder);
    if (!invoice_result.ok) {
        fprintf(stderr, "build error: %s\n", invoice_result.error);
        fatoora_error_free(invoice_result.error);
        fatoora_invoice_builder_free(&builder);
        return 1;
    }
    invoice = invoice_result.value;

    xml_result = fatoora_invoice_to_xml(&invoice);
    if (!xml_result.ok) {
        fprintf(stderr, "xml error: %s\n", xml_result.error);
        fatoora_error_free(xml_result.error);
        fatoora_invoice_free(&invoice);
        return 1;
    }
    printf("XML: %s\n", xml_result.value.ptr);
    fatoora_string_free(xml_result.value);

    fatoora_invoice_free(&invoice);
    return 0;
}
