#ifndef fatoora_InvoiceBuilder_HPP
#define fatoora_InvoiceBuilder_HPP

#include "InvoiceBuilder.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "../diplomat_runtime.hpp"
#include "Address.hpp"
#include "BindingError.hpp"
#include "FinalizedInvoice.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_InvoiceBuilder_new_result {union {fatoora::capi::InvoiceBuilder* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_new_result;
    fatoora_InvoiceBuilder_new_result fatoora_InvoiceBuilder_new(uint8_t kind, uint8_t subtype, diplomat::capi::OptionStringView original_id, diplomat::capi::OptionStringView original_uuid, diplomat::capi::OptionStringView original_date, diplomat::capi::OptionStringView reason);

    typedef struct fatoora_InvoiceBuilder_set_id_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_id_result;
    fatoora_InvoiceBuilder_set_id_result fatoora_InvoiceBuilder_set_id(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_uuid_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_uuid_result;
    fatoora_InvoiceBuilder_set_uuid_result fatoora_InvoiceBuilder_set_uuid(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_issue_datetime_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_issue_datetime_result;
    fatoora_InvoiceBuilder_set_issue_datetime_result fatoora_InvoiceBuilder_set_issue_datetime(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_currency_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_currency_result;
    fatoora_InvoiceBuilder_set_currency_result fatoora_InvoiceBuilder_set_currency(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_previous_invoice_hash_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_previous_invoice_hash_result;
    fatoora_InvoiceBuilder_set_previous_invoice_hash_result fatoora_InvoiceBuilder_set_previous_invoice_hash(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_payment_means_code_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_payment_means_code_result;
    fatoora_InvoiceBuilder_set_payment_means_code_result fatoora_InvoiceBuilder_set_payment_means_code(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_allowance_reason_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_allowance_reason_result;
    fatoora_InvoiceBuilder_allowance_reason_result fatoora_InvoiceBuilder_allowance_reason(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_invoice_level_charge_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_invoice_level_charge_result;
    fatoora_InvoiceBuilder_invoice_level_charge_result fatoora_InvoiceBuilder_invoice_level_charge(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_invoice_level_discount_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_invoice_level_discount_result;
    fatoora_InvoiceBuilder_invoice_level_discount_result fatoora_InvoiceBuilder_invoice_level_discount(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_invoice_counter_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_invoice_counter_result;
    fatoora_InvoiceBuilder_set_invoice_counter_result fatoora_InvoiceBuilder_set_invoice_counter(fatoora::capi::InvoiceBuilder* self, uint64_t value);

    typedef struct fatoora_InvoiceBuilder_set_vat_category_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_vat_category_result;
    fatoora_InvoiceBuilder_set_vat_category_result fatoora_InvoiceBuilder_set_vat_category(fatoora::capi::InvoiceBuilder* self, uint8_t value);

    typedef struct fatoora_InvoiceBuilder_flags_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_flags_result;
    fatoora_InvoiceBuilder_flags_result fatoora_InvoiceBuilder_flags(fatoora::capi::InvoiceBuilder* self, uint8_t value);

    typedef struct fatoora_InvoiceBuilder_set_note_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_note_result;
    fatoora_InvoiceBuilder_set_note_result fatoora_InvoiceBuilder_set_note(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView language, diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_allowance_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_allowance_result;
    fatoora_InvoiceBuilder_set_allowance_result fatoora_InvoiceBuilder_set_allowance(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView reason, diplomat::capi::DiplomatStringView amount);

    typedef struct fatoora_InvoiceBuilder_set_seller_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_seller_result;
    fatoora_InvoiceBuilder_set_seller_result fatoora_InvoiceBuilder_set_seller(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView name, const fatoora::capi::Address* address, diplomat::capi::DiplomatStringView vat_id, diplomat::capi::OptionStringView other_id, diplomat::capi::OptionStringView scheme);

    typedef struct fatoora_InvoiceBuilder_set_buyer_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_buyer_result;
    fatoora_InvoiceBuilder_set_buyer_result fatoora_InvoiceBuilder_set_buyer(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView name, const fatoora::capi::Address* address, diplomat::capi::OptionStringView vat_id, diplomat::capi::OptionStringView other_id, diplomat::capi::OptionStringView scheme);

    typedef struct fatoora_InvoiceBuilder_add_line_item_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_add_line_item_result;
    fatoora_InvoiceBuilder_add_line_item_result fatoora_InvoiceBuilder_add_line_item(fatoora::capi::InvoiceBuilder* self, diplomat::capi::DiplomatStringView description, diplomat::capi::DiplomatStringView quantity, diplomat::capi::DiplomatStringView unit_code, diplomat::capi::DiplomatStringView unit_price, diplomat::capi::DiplomatStringView vat_rate, uint8_t category);

    typedef struct fatoora_InvoiceBuilder_build_result {union {fatoora::capi::FinalizedInvoice* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_build_result;
    fatoora_InvoiceBuilder_build_result fatoora_InvoiceBuilder_build(fatoora::capi::InvoiceBuilder* self);

    void fatoora_InvoiceBuilder_destroy(InvoiceBuilder* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::InvoiceBuilder>, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::new_(uint8_t kind, uint8_t subtype, std::optional<std::string_view> original_id, std::optional<std::string_view> original_uuid, std::optional<std::string_view> original_date, std::optional<std::string_view> reason) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_new(kind,
        subtype,
        original_id.has_value() ? (diplomat::capi::OptionStringView{ { {original_id.value().data(), original_id.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }),
        original_uuid.has_value() ? (diplomat::capi::OptionStringView{ { {original_uuid.value().data(), original_uuid.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }),
        original_date.has_value() ? (diplomat::capi::OptionStringView{ { {original_date.value().data(), original_date.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }),
        reason.has_value() ? (diplomat::capi::OptionStringView{ { {reason.value().data(), reason.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::InvoiceBuilder>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::InvoiceBuilder>>(std::unique_ptr<fatoora::InvoiceBuilder>(fatoora::InvoiceBuilder::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::InvoiceBuilder>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_id(std::string_view value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_id(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_uuid(std::string_view value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_uuid(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_issue_datetime(std::string_view value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_issue_datetime(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_currency(std::string_view value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_currency(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_previous_invoice_hash(std::string_view value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_previous_invoice_hash(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_payment_means_code(std::string_view value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_payment_means_code(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::allowance_reason(std::string_view value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_allowance_reason(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::invoice_level_charge(std::string_view value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_invoice_level_charge(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::invoice_level_discount(std::string_view value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_invoice_level_discount(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_invoice_counter(uint64_t value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_invoice_counter(this->AsFFI(),
        value);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_vat_category(uint8_t value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_vat_category(this->AsFFI(),
        value);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::flags(uint8_t value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_flags(this->AsFFI(),
        value);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_note(std::string_view language, std::string_view value) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_note(this->AsFFI(),
        {language.data(), language.size()},
        {value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_allowance(std::string_view reason, std::string_view amount) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_allowance(this->AsFFI(),
        {reason.data(), reason.size()},
        {amount.data(), amount.size()});
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_seller(std::string_view name, const fatoora::Address& address, std::string_view vat_id, std::optional<std::string_view> other_id, std::optional<std::string_view> scheme) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_seller(this->AsFFI(),
        {name.data(), name.size()},
        address.AsFFI(),
        {vat_id.data(), vat_id.size()},
        other_id.has_value() ? (diplomat::capi::OptionStringView{ { {other_id.value().data(), other_id.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }),
        scheme.has_value() ? (diplomat::capi::OptionStringView{ { {scheme.value().data(), scheme.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::set_buyer(std::string_view name, const fatoora::Address& address, std::optional<std::string_view> vat_id, std::optional<std::string_view> other_id, std::optional<std::string_view> scheme) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_set_buyer(this->AsFFI(),
        {name.data(), name.size()},
        address.AsFFI(),
        vat_id.has_value() ? (diplomat::capi::OptionStringView{ { {vat_id.value().data(), vat_id.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }),
        other_id.has_value() ? (diplomat::capi::OptionStringView{ { {other_id.value().data(), other_id.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }),
        scheme.has_value() ? (diplomat::capi::OptionStringView{ { {scheme.value().data(), scheme.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::add_line_item(std::string_view description, std::string_view quantity, std::string_view unit_code, std::string_view unit_price, std::string_view vat_rate, uint8_t category) {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_add_line_item(this->AsFFI(),
        {description.data(), description.size()},
        {quantity.data(), quantity.size()},
        {unit_code.data(), unit_code.size()},
        {unit_price.data(), unit_price.size()},
        {vat_rate.data(), vat_rate.size()},
        category);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceBuilder::build() {
    auto result = fatoora::capi::fatoora_InvoiceBuilder_build(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::FinalizedInvoice>>(std::unique_ptr<fatoora::FinalizedInvoice>(fatoora::FinalizedInvoice::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::InvoiceBuilder* fatoora::InvoiceBuilder::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::InvoiceBuilder*>(this);
}

inline fatoora::capi::InvoiceBuilder* fatoora::InvoiceBuilder::AsFFI() {
    return reinterpret_cast<fatoora::capi::InvoiceBuilder*>(this);
}

inline const fatoora::InvoiceBuilder* fatoora::InvoiceBuilder::FromFFI(const fatoora::capi::InvoiceBuilder* ptr) {
    return reinterpret_cast<const fatoora::InvoiceBuilder*>(ptr);
}

inline fatoora::InvoiceBuilder* fatoora::InvoiceBuilder::FromFFI(fatoora::capi::InvoiceBuilder* ptr) {
    return reinterpret_cast<fatoora::InvoiceBuilder*>(ptr);
}

inline void fatoora::InvoiceBuilder::operator delete(void* ptr) {
    fatoora::capi::fatoora_InvoiceBuilder_destroy(reinterpret_cast<fatoora::capi::InvoiceBuilder*>(ptr));
}


#endif // fatoora_InvoiceBuilder_HPP
