#include "fatoora/Address.hpp"
#include "fatoora/BindingError.hpp"
#include "fatoora/Bytes.hpp"
#include "fatoora/BytesList.hpp"
#include "fatoora/Config.hpp"
#include "fatoora/Csr.hpp"
#include "fatoora/CsrProperties.hpp"
#include "fatoora/FinalizedInvoice.hpp"
#include "fatoora/InvoiceBuilder.hpp"
#include "fatoora/InvoiceData.hpp"
#include "fatoora/InvoiceLineItem.hpp"
#include "fatoora/Party.hpp"
#include "fatoora/SignedInvoice.hpp"
#include "fatoora/SigningKey.hpp"
#include <algorithm>
#include <cassert>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

static auto builder() {
    auto b = fatoora::InvoiceBuilder::new_(0, 1, std::nullopt, std::nullopt,
        std::nullopt, std::nullopt).ok().value();
    assert(b->set_id("INV-1").is_ok());
    assert(b->set_uuid("8e6000cf-1a98-4174-b3e7-b5d5954bc10d").is_ok());
    assert(b->set_issue_datetime("2024-01-01T12:30:00Z").is_ok());
    assert(b->set_currency("SAR").is_ok());
    assert(b->set_previous_invoice_hash("hash").is_ok());
    assert(b->set_invoice_counter(1).is_ok());
    assert(b->set_payment_means_code("10").is_ok());
    assert(b->set_vat_category(1).is_ok());
    auto address = fatoora::Address::new_("SA", "Riyadh", "King Fahd", "1234", "12222",
        std::nullopt, std::nullopt, "Olaya").ok().value();
    assert(b->set_seller("Seller", *address, "399999999900003", "7003339333", "CRN").is_ok());
    return b;
}

static void invoice_contract() {
    assert(fatoora::Config::new_(255).err().value()->code() == 1);
    assert(fatoora::InvoiceBuilder::new_(255, 1, std::nullopt, std::nullopt,
        std::nullopt, std::nullopt).err().value()->code() == 1);
    assert(fatoora::InvoiceBuilder::new_(0, 255, std::nullopt, std::nullopt,
        std::nullopt, std::nullopt).err().value()->code() == 1);
    auto b = builder();
    assert(b->set_vat_category(255).err().value()->code() == 1);
    assert(b->add_line_item(std::string(1, static_cast<char>(0xff)), "3", "PCE", "1", "15", 1)
        .err().value()->code() == 1);
    assert(b->add_line_item(std::string("a\0b", 3), "3", "PCE", "1", "15", 1)
        .err().value()->code() == 1);
    assert(b->add_line_item("Item", "3", "PCE", "1", "15", 255).err().value()->code() == 1);
    auto error = b->add_line_item("Item", "3", "PCE", "invalid", "15", 1).err().value();
    assert(error->code() == 1);
    auto details = error->details_json();
    error.reset();
    assert(details.find("invalid_decimal") != std::string::npos);
    assert(b->add_line_item("Item", "3", "PCE", "0.3333", "15", 1).is_ok());
    auto invoice = b->build().ok().value();
    auto xml = invoice->xml().ok().value();
    auto data = invoice->data().ok().value();
    invoice.reset();
    auto seller = data->seller().ok().value();
    auto line = data->line_item(0).ok().value();
    assert(data->line_item(1).err().value()->code() == 1);
    data.reset();
    auto address = seller->address().ok().value();
    seller.reset();
    assert(address->city().ok().value() == "Riyadh");
    assert(line->unit_price().ok().value() == "0.3333");
    assert(xml.find(">0.3333</cbc:PriceAmount>") != std::string::npos);
    assert(xml.find(">1.15</cbc:TaxInclusiveAmount>") != std::string::npos);
    assert(b->build().err().value()->code() == 1);
    assert(b->set_id("again").err().value()->code() == 1);
    b = builder();
    assert(!b->build().is_ok());
    assert(b->build().err().value()->code() == 1);
}

static void signed_contract(const char *path) {
    std::ifstream input(path, std::ios::binary);
    assert(input);
    std::string xml((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    auto invoice = fatoora::SignedInvoice::from_xml(xml).ok().value();
    auto copied = invoice->xml().ok().value();
    auto data = invoice->data().ok().value();
    auto owned = invoice->into_xml().ok().value();
    assert(invoice->xml().err().value()->code() == 1);
    assert(invoice->into_xml().err().value()->code() == 1);
    assert(invoice->data().err().value()->code() == 1);
    invoice.reset();
    assert(copied == xml && owned == xml);
    assert(!data->id().ok().value().empty());
    auto seller = data->seller().ok().value();
    data.reset();
    assert(!seller->name().ok().value().empty());
}

static void crypto_contract() {
    auto key = fatoora::SigningKey::generate().ok().value();
    auto der = key->to_der().ok().value();
    auto parsed_key = fatoora::SigningKey::from_der(der->as_slice()).ok().value();
    auto parsed_der = parsed_key->to_der().ok().value();
    auto expected = der->as_slice();
    auto actual = parsed_der->as_slice();
    assert(expected.size() == actual.size());
    assert(std::equal(expected.begin(), expected.end(), actual.begin()));
    key.reset();
    der.reset();
    auto props = fatoora::CsrProperties::new_("TST-886431145-399999999900003",
        "1-TST|2-TST|3-ed22f1d8-e6a2-1118-9b58-d9a8f11e445f", "399999999900003",
        "Riyadh Branch", "Maximum Speed Tech Supply LTD", "SA", "1100", "RRRD2929",
        "Supply activities").ok().value();
    assert(props->build(*parsed_key, 255).err().value()->code() == 1);
    auto csr = props->build(*parsed_key, 0).ok().value();
    props.reset();
    parsed_key.reset();
    auto csr_der = csr->to_der().ok().value();
    auto parsed_csr = fatoora::Csr::from_der(csr_der->as_slice()).ok().value();
    auto again = parsed_csr->to_der().ok().value();
    expected = csr_der->as_slice();
    actual = again->as_slice();
    assert(expected.size() == actual.size());
    assert(std::equal(expected.begin(), expected.end(), actual.begin()));
    auto extensions = csr->extension_values_der().ok().value();
    assert(!extensions->is_empty());
    assert(extensions->get(extensions->len()).err().value()->code() == 1);
    auto extension = extensions->get(0).ok().value();
    extensions.reset();
    csr.reset();
    assert(extension->as_slice().size() > 0);
    assert(!parsed_csr->subject_string().ok().value().empty());
}

int main(int argc, char **argv) {
    assert(argc == 2 && "pass a signed XML fixture path");
    invoice_contract();
    signed_contract(argv[1]);
    crypto_contract();
}
