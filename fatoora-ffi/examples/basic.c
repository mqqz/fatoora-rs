#include <stdio.h>

#define FATOORA_FFI_NO_PREFIX
#include "fatoora.h"

/* Takes ownership of an error and releases both returned string copies. */
static void report_error(Error *error) {
    FatooraString message = error_message(error);
    FatooraString details = error_details_json(error);
    fprintf(stderr, "%s\n%s\n", message.ptr ? message.ptr : "unknown error",
            details.ptr ? details.ptr : "{}");
    string_free(message);
    string_free(details);
    error_free(error);
}

static bool check(FfiResult_bool result) {
    if (!result.ok) {
        report_error(result.error);
    }
    return result.ok;
}

int main(void) {
    FfiResult_FfiInvoiceBuilder builder_result = invoice_builder_new(
        InvoiceTypeKind_Tax, InvoiceSubType_Simplified, NULL, NULL, NULL, NULL);
    if (!builder_result.ok) {
        report_error(builder_result.error);
        return 1;
    }
    InvoiceBuilder builder = builder_result.value;

    if (!check(invoice_builder_set_id(&builder, "INV-1")) ||
        !check(invoice_builder_set_uuid(&builder, "123e4567-e89b-12d3-a456-426614174000")) ||
        !check(invoice_builder_set_issue_datetime(&builder, "2024-01-01T12:30:00Z")) ||
        !check(invoice_builder_set_currency(&builder, "SAR")) ||
        !check(invoice_builder_set_previous_hash(&builder, "hash")) ||
        !check(invoice_builder_set_invoice_counter(&builder, 1)) ||
        !check(invoice_builder_set_payment_means_code(&builder, "10")) ||
        !check(invoice_builder_set_vat_category(&builder, VatCategory_Standard)) ||
        !check(invoice_builder_set_seller(
            &builder, "Acme Inc", "SAU", "Riyadh", "King Fahd", NULL, "1234",
            NULL, "12222", NULL, NULL, "399999999900003", NULL, NULL)) ||
        !check(invoice_builder_add_line_item(
            &builder, "Item", "1", "PCE", "100", "15", VatCategory_Standard))) {
        invoice_builder_free(&builder);
        return 1;
    }

    FfiResult_FfiFinalizedInvoice invoice_result = invoice_builder_build(&builder);
    invoice_builder_free(&builder);
    if (!invoice_result.ok) {
        report_error(invoice_result.error);
        return 1;
    }
    FinalizedInvoice invoice = invoice_result.value;
    FfiResult_FfiString xml_result = invoice_to_xml(&invoice);
    invoice_free(&invoice);
    if (!xml_result.ok) {
        report_error(xml_result.error);
        return 1;
    }
    printf("XML: %s\n", xml_result.value.ptr);
    string_free(xml_result.value);
    return 0;
}
