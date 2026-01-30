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

    if (!fatoora_invoice_builder_set_id(&builder, "INV-1").ok) {
        fprintf(stderr, "set id failed\n");
        fatoora_invoice_builder_free(&builder);
        return 1;
    }
    if (!fatoora_invoice_builder_set_uuid(&builder, "123e4567-e89b-12d3-a456-426614174000").ok) {
        fprintf(stderr, "set uuid failed\n");
        fatoora_invoice_builder_free(&builder);
        return 1;
    }
    if (!fatoora_invoice_builder_set_issue_datetime(&builder, "2024-01-01T12:30:00Z").ok) {
        fprintf(stderr, "set issue datetime failed\n");
        fatoora_invoice_builder_free(&builder);
        return 1;
    }
    if (!fatoora_invoice_builder_set_currency(&builder, "SAR").ok) {
        fprintf(stderr, "set currency failed\n");
        fatoora_invoice_builder_free(&builder);
        return 1;
    }
    if (!fatoora_invoice_builder_set_previous_hash(&builder, "hash").ok) {
        fprintf(stderr, "set previous hash failed\n");
        fatoora_invoice_builder_free(&builder);
        return 1;
    }
    if (!fatoora_invoice_builder_set_invoice_counter(&builder, 1).ok) {
        fprintf(stderr, "set invoice counter failed\n");
        fatoora_invoice_builder_free(&builder);
        return 1;
    }
    if (!fatoora_invoice_builder_set_payment_means_code(&builder, "10").ok) {
        fprintf(stderr, "set payment means failed\n");
        fatoora_invoice_builder_free(&builder);
        return 1;
    }
    if (!fatoora_invoice_builder_set_vat_category(&builder, VatCategory_Standard).ok) {
        fprintf(stderr, "set vat category failed\n");
        fatoora_invoice_builder_free(&builder);
        return 1;
    }
    if (!fatoora_invoice_builder_set_seller(
            &builder,
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
            NULL
        ).ok) {
        fprintf(stderr, "set seller failed\n");
        fatoora_invoice_builder_free(&builder);
        return 1;
    }
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
    fatoora_invoice_builder_free(&builder);
    return 0;
}
