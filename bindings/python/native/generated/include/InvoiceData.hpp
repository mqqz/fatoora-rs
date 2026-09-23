#ifndef _NATIVE_InvoiceData_HPP
#define _NATIVE_InvoiceData_HPP

#include "InvoiceData.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "BindingError.hpp"
#include "InvoiceLineItem.hpp"
#include "InvoiceNote.hpp"
#include "OriginalInvoiceRef.hpp"
#include "Party.hpp"
#include "Text.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_InvoiceData_id_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_id_result;
    fatoora_InvoiceData_id_result fatoora_InvoiceData_id(const _native::capi::InvoiceData* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_uuid_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_uuid_result;
    fatoora_InvoiceData_uuid_result fatoora_InvoiceData_uuid(const _native::capi::InvoiceData* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_previous_invoice_hash_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_previous_invoice_hash_result;
    fatoora_InvoiceData_previous_invoice_hash_result fatoora_InvoiceData_previous_invoice_hash(const _native::capi::InvoiceData* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_payment_means_code_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_payment_means_code_result;
    fatoora_InvoiceData_payment_means_code_result fatoora_InvoiceData_payment_means_code(const _native::capi::InvoiceData* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_currency_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_currency_result;
    fatoora_InvoiceData_currency_result fatoora_InvoiceData_currency(const _native::capi::InvoiceData* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_issue_datetime_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_issue_datetime_result;
    fatoora_InvoiceData_issue_datetime_result fatoora_InvoiceData_issue_datetime(const _native::capi::InvoiceData* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_invoice_level_charge_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_invoice_level_charge_result;
    fatoora_InvoiceData_invoice_level_charge_result fatoora_InvoiceData_invoice_level_charge(const _native::capi::InvoiceData* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_invoice_level_discount_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_invoice_level_discount_result;
    fatoora_InvoiceData_invoice_level_discount_result fatoora_InvoiceData_invoice_level_discount(const _native::capi::InvoiceData* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_allowance_reason_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_allowance_reason_result;
    fatoora_InvoiceData_allowance_reason_result fatoora_InvoiceData_allowance_reason(const _native::capi::InvoiceData* self);

    uint64_t fatoora_InvoiceData_invoice_counter(const _native::capi::InvoiceData* self);

    uint8_t fatoora_InvoiceData_vat_category(const _native::capi::InvoiceData* self);

    uint8_t fatoora_InvoiceData_flags_raw(const _native::capi::InvoiceData* self);

    uint8_t fatoora_InvoiceData_invoice_type_kind(const _native::capi::InvoiceData* self);

    uint8_t fatoora_InvoiceData_invoice_sub_type(const _native::capi::InvoiceData* self);

    typedef struct fatoora_InvoiceData_seller_result {union {_native::capi::Party* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_seller_result;
    fatoora_InvoiceData_seller_result fatoora_InvoiceData_seller(const _native::capi::InvoiceData* self);

    typedef struct fatoora_InvoiceData_buyer_result {union {_native::capi::Party* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_buyer_result;
    fatoora_InvoiceData_buyer_result fatoora_InvoiceData_buyer(const _native::capi::InvoiceData* self);

    typedef struct fatoora_InvoiceData_note_result {union {_native::capi::InvoiceNote* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_note_result;
    fatoora_InvoiceData_note_result fatoora_InvoiceData_note(const _native::capi::InvoiceData* self);

    size_t fatoora_InvoiceData_line_items_len(const _native::capi::InvoiceData* self);

    typedef struct fatoora_InvoiceData_line_item_result {union {_native::capi::InvoiceLineItem* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_line_item_result;
    fatoora_InvoiceData_line_item_result fatoora_InvoiceData_line_item(const _native::capi::InvoiceData* self, size_t index);

    typedef struct fatoora_InvoiceData_original_invoice_ref_result {union {_native::capi::OriginalInvoiceRef* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_original_invoice_ref_result;
    fatoora_InvoiceData_original_invoice_ref_result fatoora_InvoiceData_original_invoice_ref(const _native::capi::InvoiceData* self);

    typedef struct fatoora_InvoiceData_original_invoice_reason_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_original_invoice_reason_result;
    fatoora_InvoiceData_original_invoice_reason_result fatoora_InvoiceData_original_invoice_reason(const _native::capi::InvoiceData* self);

    void fatoora_InvoiceData_destroy(InvoiceData* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceData::id() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceData_id(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceData::id_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceData_id(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceData::uuid() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceData_uuid(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceData::uuid_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceData_uuid(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceData::previous_invoice_hash() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceData_previous_invoice_hash(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceData::previous_invoice_hash_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceData_previous_invoice_hash(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceData::payment_means_code() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceData_payment_means_code(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceData::payment_means_code_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceData_payment_means_code(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceData::currency() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceData_currency(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceData::currency_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceData_currency(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceData::issue_datetime() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceData_issue_datetime(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceData::issue_datetime_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceData_issue_datetime(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceData::invoice_level_charge() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceData_invoice_level_charge(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceData::invoice_level_charge_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceData_invoice_level_charge(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceData::invoice_level_discount() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceData_invoice_level_discount(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceData::invoice_level_discount_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceData_invoice_level_discount(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::InvoiceData::allowance_reason() const {
    auto result = _native::capi::fatoora_InvoiceData_allowance_reason(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline uint64_t _native::InvoiceData::invoice_counter() const {
    auto result = _native::capi::fatoora_InvoiceData_invoice_counter(this->AsFFI());
    return result;
}

inline uint8_t _native::InvoiceData::vat_category() const {
    auto result = _native::capi::fatoora_InvoiceData_vat_category(this->AsFFI());
    return result;
}

inline uint8_t _native::InvoiceData::flags_raw() const {
    auto result = _native::capi::fatoora_InvoiceData_flags_raw(this->AsFFI());
    return result;
}

inline uint8_t _native::InvoiceData::invoice_type_kind() const {
    auto result = _native::capi::fatoora_InvoiceData_invoice_type_kind(this->AsFFI());
    return result;
}

inline uint8_t _native::InvoiceData::invoice_sub_type() const {
    auto result = _native::capi::fatoora_InvoiceData_invoice_sub_type(this->AsFFI());
    return result;
}

inline _native::diplomat::result<std::unique_ptr<_native::Party>, std::unique_ptr<_native::BindingError>> _native::InvoiceData::seller() const {
    auto result = _native::capi::fatoora_InvoiceData_seller(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Party>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Party>>(std::unique_ptr<_native::Party>(_native::Party::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Party>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Party>, std::unique_ptr<_native::BindingError>> _native::InvoiceData::buyer() const {
    auto result = _native::capi::fatoora_InvoiceData_buyer(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Party>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Party>>(std::unique_ptr<_native::Party>(_native::Party::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Party>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::InvoiceNote>, std::unique_ptr<_native::BindingError>> _native::InvoiceData::note() const {
    auto result = _native::capi::fatoora_InvoiceData_note(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::InvoiceNote>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::InvoiceNote>>(std::unique_ptr<_native::InvoiceNote>(_native::InvoiceNote::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::InvoiceNote>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline size_t _native::InvoiceData::line_items_len() const {
    auto result = _native::capi::fatoora_InvoiceData_line_items_len(this->AsFFI());
    return result;
}

inline _native::diplomat::result<std::unique_ptr<_native::InvoiceLineItem>, std::unique_ptr<_native::BindingError>> _native::InvoiceData::line_item(size_t index) const {
    auto result = _native::capi::fatoora_InvoiceData_line_item(this->AsFFI(),
        index);
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::InvoiceLineItem>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::InvoiceLineItem>>(std::unique_ptr<_native::InvoiceLineItem>(_native::InvoiceLineItem::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::InvoiceLineItem>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::OriginalInvoiceRef>, std::unique_ptr<_native::BindingError>> _native::InvoiceData::original_invoice_ref() const {
    auto result = _native::capi::fatoora_InvoiceData_original_invoice_ref(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::OriginalInvoiceRef>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::OriginalInvoiceRef>>(std::unique_ptr<_native::OriginalInvoiceRef>(_native::OriginalInvoiceRef::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::OriginalInvoiceRef>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::InvoiceData::original_invoice_reason() const {
    auto result = _native::capi::fatoora_InvoiceData_original_invoice_reason(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::InvoiceData* _native::InvoiceData::AsFFI() const {
    return reinterpret_cast<const _native::capi::InvoiceData*>(this);
}

inline _native::capi::InvoiceData* _native::InvoiceData::AsFFI() {
    return reinterpret_cast<_native::capi::InvoiceData*>(this);
}

inline const _native::InvoiceData* _native::InvoiceData::FromFFI(const _native::capi::InvoiceData* ptr) {
    return reinterpret_cast<const _native::InvoiceData*>(ptr);
}

inline _native::InvoiceData* _native::InvoiceData::FromFFI(_native::capi::InvoiceData* ptr) {
    return reinterpret_cast<_native::InvoiceData*>(ptr);
}

inline void _native::InvoiceData::operator delete(void* ptr) {
    _native::capi::fatoora_InvoiceData_destroy(reinterpret_cast<_native::capi::InvoiceData*>(ptr));
}


#endif // _NATIVE_InvoiceData_HPP
