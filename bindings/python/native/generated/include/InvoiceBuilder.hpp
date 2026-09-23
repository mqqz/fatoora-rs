#ifndef _NATIVE_InvoiceBuilder_HPP
#define _NATIVE_InvoiceBuilder_HPP

#include "InvoiceBuilder.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "Address.hpp"
#include "BindingError.hpp"
#include "FinalizedInvoice.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_InvoiceBuilder_new_result {union {_native::capi::InvoiceBuilder* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_new_result;
    fatoora_InvoiceBuilder_new_result fatoora_InvoiceBuilder_new(uint8_t kind, uint8_t subtype, _native::diplomat::capi::OptionStringView original_id, _native::diplomat::capi::OptionStringView original_uuid, _native::diplomat::capi::OptionStringView original_date, _native::diplomat::capi::OptionStringView reason);

    typedef struct fatoora_InvoiceBuilder_set_id_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_id_result;
    fatoora_InvoiceBuilder_set_id_result fatoora_InvoiceBuilder_set_id(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_uuid_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_uuid_result;
    fatoora_InvoiceBuilder_set_uuid_result fatoora_InvoiceBuilder_set_uuid(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_issue_datetime_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_issue_datetime_result;
    fatoora_InvoiceBuilder_set_issue_datetime_result fatoora_InvoiceBuilder_set_issue_datetime(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_currency_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_currency_result;
    fatoora_InvoiceBuilder_set_currency_result fatoora_InvoiceBuilder_set_currency(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_previous_invoice_hash_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_previous_invoice_hash_result;
    fatoora_InvoiceBuilder_set_previous_invoice_hash_result fatoora_InvoiceBuilder_set_previous_invoice_hash(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_payment_means_code_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_payment_means_code_result;
    fatoora_InvoiceBuilder_set_payment_means_code_result fatoora_InvoiceBuilder_set_payment_means_code(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_allowance_reason_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_allowance_reason_result;
    fatoora_InvoiceBuilder_allowance_reason_result fatoora_InvoiceBuilder_allowance_reason(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_invoice_level_charge_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_invoice_level_charge_result;
    fatoora_InvoiceBuilder_invoice_level_charge_result fatoora_InvoiceBuilder_invoice_level_charge(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_invoice_level_discount_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_invoice_level_discount_result;
    fatoora_InvoiceBuilder_invoice_level_discount_result fatoora_InvoiceBuilder_invoice_level_discount(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_invoice_counter_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_invoice_counter_result;
    fatoora_InvoiceBuilder_set_invoice_counter_result fatoora_InvoiceBuilder_set_invoice_counter(_native::capi::InvoiceBuilder* self, uint64_t value);

    typedef struct fatoora_InvoiceBuilder_set_vat_category_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_vat_category_result;
    fatoora_InvoiceBuilder_set_vat_category_result fatoora_InvoiceBuilder_set_vat_category(_native::capi::InvoiceBuilder* self, uint8_t value);

    typedef struct fatoora_InvoiceBuilder_flags_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_flags_result;
    fatoora_InvoiceBuilder_flags_result fatoora_InvoiceBuilder_flags(_native::capi::InvoiceBuilder* self, uint8_t value);

    typedef struct fatoora_InvoiceBuilder_set_note_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_note_result;
    fatoora_InvoiceBuilder_set_note_result fatoora_InvoiceBuilder_set_note(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView language, _native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_InvoiceBuilder_set_allowance_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_allowance_result;
    fatoora_InvoiceBuilder_set_allowance_result fatoora_InvoiceBuilder_set_allowance(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView reason, _native::diplomat::capi::DiplomatStringView amount);

    typedef struct fatoora_InvoiceBuilder_set_seller_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_seller_result;
    fatoora_InvoiceBuilder_set_seller_result fatoora_InvoiceBuilder_set_seller(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView name, const _native::capi::Address* address, _native::diplomat::capi::DiplomatStringView vat_id, _native::diplomat::capi::OptionStringView other_id, _native::diplomat::capi::OptionStringView scheme);

    typedef struct fatoora_InvoiceBuilder_set_buyer_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_set_buyer_result;
    fatoora_InvoiceBuilder_set_buyer_result fatoora_InvoiceBuilder_set_buyer(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView name, const _native::capi::Address* address, _native::diplomat::capi::OptionStringView vat_id, _native::diplomat::capi::OptionStringView other_id, _native::diplomat::capi::OptionStringView scheme);

    typedef struct fatoora_InvoiceBuilder_add_line_item_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_add_line_item_result;
    fatoora_InvoiceBuilder_add_line_item_result fatoora_InvoiceBuilder_add_line_item(_native::capi::InvoiceBuilder* self, _native::diplomat::capi::DiplomatStringView description, _native::diplomat::capi::DiplomatStringView quantity, _native::diplomat::capi::DiplomatStringView unit_code, _native::diplomat::capi::DiplomatStringView unit_price, _native::diplomat::capi::DiplomatStringView vat_rate, uint8_t category);

    typedef struct fatoora_InvoiceBuilder_build_result {union {_native::capi::FinalizedInvoice* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceBuilder_build_result;
    fatoora_InvoiceBuilder_build_result fatoora_InvoiceBuilder_build(_native::capi::InvoiceBuilder* self);

    void fatoora_InvoiceBuilder_destroy(InvoiceBuilder* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::InvoiceBuilder>, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::new_(uint8_t kind, uint8_t subtype, std::optional<std::string_view> original_id, std::optional<std::string_view> original_uuid, std::optional<std::string_view> original_date, std::optional<std::string_view> reason) {
    auto result = _native::capi::fatoora_InvoiceBuilder_new(kind,
        subtype,
        original_id.has_value() ? (_native::diplomat::capi::OptionStringView{ { {original_id.value().data(), original_id.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        original_uuid.has_value() ? (_native::diplomat::capi::OptionStringView{ { {original_uuid.value().data(), original_uuid.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        original_date.has_value() ? (_native::diplomat::capi::OptionStringView{ { {original_date.value().data(), original_date.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        reason.has_value() ? (_native::diplomat::capi::OptionStringView{ { {reason.value().data(), reason.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::InvoiceBuilder>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::InvoiceBuilder>>(std::unique_ptr<_native::InvoiceBuilder>(_native::InvoiceBuilder::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::InvoiceBuilder>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_id(std::string_view value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_id(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_uuid(std::string_view value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_uuid(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_issue_datetime(std::string_view value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_issue_datetime(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_currency(std::string_view value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_currency(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_previous_invoice_hash(std::string_view value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_previous_invoice_hash(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_payment_means_code(std::string_view value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_payment_means_code(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::allowance_reason(std::string_view value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_allowance_reason(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::invoice_level_charge(std::string_view value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_invoice_level_charge(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::invoice_level_discount(std::string_view value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_invoice_level_discount(this->AsFFI(),
        {value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_invoice_counter(uint64_t value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_invoice_counter(this->AsFFI(),
        value);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_vat_category(uint8_t value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_vat_category(this->AsFFI(),
        value);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::flags(uint8_t value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_flags(this->AsFFI(),
        value);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_note(std::string_view language, std::string_view value) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_note(this->AsFFI(),
        {language.data(), language.size()},
        {value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_allowance(std::string_view reason, std::string_view amount) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_allowance(this->AsFFI(),
        {reason.data(), reason.size()},
        {amount.data(), amount.size()});
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_seller(std::string_view name, const _native::Address& address, std::string_view vat_id, std::optional<std::string_view> other_id, std::optional<std::string_view> scheme) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_seller(this->AsFFI(),
        {name.data(), name.size()},
        address.AsFFI(),
        {vat_id.data(), vat_id.size()},
        other_id.has_value() ? (_native::diplomat::capi::OptionStringView{ { {other_id.value().data(), other_id.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        scheme.has_value() ? (_native::diplomat::capi::OptionStringView{ { {scheme.value().data(), scheme.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::set_buyer(std::string_view name, const _native::Address& address, std::optional<std::string_view> vat_id, std::optional<std::string_view> other_id, std::optional<std::string_view> scheme) {
    auto result = _native::capi::fatoora_InvoiceBuilder_set_buyer(this->AsFFI(),
        {name.data(), name.size()},
        address.AsFFI(),
        vat_id.has_value() ? (_native::diplomat::capi::OptionStringView{ { {vat_id.value().data(), vat_id.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        other_id.has_value() ? (_native::diplomat::capi::OptionStringView{ { {other_id.value().data(), other_id.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        scheme.has_value() ? (_native::diplomat::capi::OptionStringView{ { {scheme.value().data(), scheme.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::add_line_item(std::string_view description, std::string_view quantity, std::string_view unit_code, std::string_view unit_price, std::string_view vat_rate, uint8_t category) {
    auto result = _native::capi::fatoora_InvoiceBuilder_add_line_item(this->AsFFI(),
        {description.data(), description.size()},
        {quantity.data(), quantity.size()},
        {unit_code.data(), unit_code.size()},
        {unit_price.data(), unit_price.size()},
        {vat_rate.data(), vat_rate.size()},
        category);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>> _native::InvoiceBuilder::build() {
    auto result = _native::capi::fatoora_InvoiceBuilder_build(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::FinalizedInvoice>>(std::unique_ptr<_native::FinalizedInvoice>(_native::FinalizedInvoice::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::InvoiceBuilder* _native::InvoiceBuilder::AsFFI() const {
    return reinterpret_cast<const _native::capi::InvoiceBuilder*>(this);
}

inline _native::capi::InvoiceBuilder* _native::InvoiceBuilder::AsFFI() {
    return reinterpret_cast<_native::capi::InvoiceBuilder*>(this);
}

inline const _native::InvoiceBuilder* _native::InvoiceBuilder::FromFFI(const _native::capi::InvoiceBuilder* ptr) {
    return reinterpret_cast<const _native::InvoiceBuilder*>(ptr);
}

inline _native::InvoiceBuilder* _native::InvoiceBuilder::FromFFI(_native::capi::InvoiceBuilder* ptr) {
    return reinterpret_cast<_native::InvoiceBuilder*>(ptr);
}

inline void _native::InvoiceBuilder::operator delete(void* ptr) {
    _native::capi::fatoora_InvoiceBuilder_destroy(reinterpret_cast<_native::capi::InvoiceBuilder*>(ptr));
}


#endif // _NATIVE_InvoiceBuilder_HPP
