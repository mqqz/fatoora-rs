#ifndef fatoora_InvoiceData_HPP
#define fatoora_InvoiceData_HPP

#include "InvoiceData.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "../diplomat_runtime.hpp"
#include "BindingError.hpp"
#include "InvoiceLineItem.hpp"
#include "InvoiceNote.hpp"
#include "OriginalInvoiceRef.hpp"
#include "Party.hpp"
#include "Text.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_InvoiceData_id_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_id_result;
    fatoora_InvoiceData_id_result fatoora_InvoiceData_id(const fatoora::capi::InvoiceData* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_uuid_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_uuid_result;
    fatoora_InvoiceData_uuid_result fatoora_InvoiceData_uuid(const fatoora::capi::InvoiceData* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_previous_invoice_hash_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_previous_invoice_hash_result;
    fatoora_InvoiceData_previous_invoice_hash_result fatoora_InvoiceData_previous_invoice_hash(const fatoora::capi::InvoiceData* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_payment_means_code_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_payment_means_code_result;
    fatoora_InvoiceData_payment_means_code_result fatoora_InvoiceData_payment_means_code(const fatoora::capi::InvoiceData* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_currency_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_currency_result;
    fatoora_InvoiceData_currency_result fatoora_InvoiceData_currency(const fatoora::capi::InvoiceData* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_issue_datetime_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_issue_datetime_result;
    fatoora_InvoiceData_issue_datetime_result fatoora_InvoiceData_issue_datetime(const fatoora::capi::InvoiceData* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_invoice_level_charge_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_invoice_level_charge_result;
    fatoora_InvoiceData_invoice_level_charge_result fatoora_InvoiceData_invoice_level_charge(const fatoora::capi::InvoiceData* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_invoice_level_discount_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_invoice_level_discount_result;
    fatoora_InvoiceData_invoice_level_discount_result fatoora_InvoiceData_invoice_level_discount(const fatoora::capi::InvoiceData* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceData_allowance_reason_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_allowance_reason_result;
    fatoora_InvoiceData_allowance_reason_result fatoora_InvoiceData_allowance_reason(const fatoora::capi::InvoiceData* self);

    uint64_t fatoora_InvoiceData_invoice_counter(const fatoora::capi::InvoiceData* self);

    uint8_t fatoora_InvoiceData_vat_category(const fatoora::capi::InvoiceData* self);

    uint8_t fatoora_InvoiceData_flags_raw(const fatoora::capi::InvoiceData* self);

    uint8_t fatoora_InvoiceData_invoice_type_kind(const fatoora::capi::InvoiceData* self);

    uint8_t fatoora_InvoiceData_invoice_sub_type(const fatoora::capi::InvoiceData* self);

    typedef struct fatoora_InvoiceData_seller_result {union {fatoora::capi::Party* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_seller_result;
    fatoora_InvoiceData_seller_result fatoora_InvoiceData_seller(const fatoora::capi::InvoiceData* self);

    typedef struct fatoora_InvoiceData_buyer_result {union {fatoora::capi::Party* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_buyer_result;
    fatoora_InvoiceData_buyer_result fatoora_InvoiceData_buyer(const fatoora::capi::InvoiceData* self);

    typedef struct fatoora_InvoiceData_note_result {union {fatoora::capi::InvoiceNote* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_note_result;
    fatoora_InvoiceData_note_result fatoora_InvoiceData_note(const fatoora::capi::InvoiceData* self);

    size_t fatoora_InvoiceData_line_items_len(const fatoora::capi::InvoiceData* self);

    typedef struct fatoora_InvoiceData_line_item_result {union {fatoora::capi::InvoiceLineItem* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_line_item_result;
    fatoora_InvoiceData_line_item_result fatoora_InvoiceData_line_item(const fatoora::capi::InvoiceData* self, size_t index);

    typedef struct fatoora_InvoiceData_original_invoice_ref_result {union {fatoora::capi::OriginalInvoiceRef* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_original_invoice_ref_result;
    fatoora_InvoiceData_original_invoice_ref_result fatoora_InvoiceData_original_invoice_ref(const fatoora::capi::InvoiceData* self);

    typedef struct fatoora_InvoiceData_original_invoice_reason_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceData_original_invoice_reason_result;
    fatoora_InvoiceData_original_invoice_reason_result fatoora_InvoiceData_original_invoice_reason(const fatoora::capi::InvoiceData* self);

    void fatoora_InvoiceData_destroy(InvoiceData* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::id() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceData_id(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::id_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceData_id(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::uuid() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceData_uuid(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::uuid_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceData_uuid(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::previous_invoice_hash() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceData_previous_invoice_hash(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::previous_invoice_hash_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceData_previous_invoice_hash(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::payment_means_code() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceData_payment_means_code(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::payment_means_code_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceData_payment_means_code(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::currency() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceData_currency(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::currency_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceData_currency(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::issue_datetime() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceData_issue_datetime(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::issue_datetime_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceData_issue_datetime(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::invoice_level_charge() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceData_invoice_level_charge(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::invoice_level_charge_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceData_invoice_level_charge(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::invoice_level_discount() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceData_invoice_level_discount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::invoice_level_discount_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceData_invoice_level_discount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::allowance_reason() const {
    auto result = fatoora::capi::fatoora_InvoiceData_allowance_reason(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline uint64_t fatoora::InvoiceData::invoice_counter() const {
    auto result = fatoora::capi::fatoora_InvoiceData_invoice_counter(this->AsFFI());
    return result;
}

inline uint8_t fatoora::InvoiceData::vat_category() const {
    auto result = fatoora::capi::fatoora_InvoiceData_vat_category(this->AsFFI());
    return result;
}

inline uint8_t fatoora::InvoiceData::flags_raw() const {
    auto result = fatoora::capi::fatoora_InvoiceData_flags_raw(this->AsFFI());
    return result;
}

inline uint8_t fatoora::InvoiceData::invoice_type_kind() const {
    auto result = fatoora::capi::fatoora_InvoiceData_invoice_type_kind(this->AsFFI());
    return result;
}

inline uint8_t fatoora::InvoiceData::invoice_sub_type() const {
    auto result = fatoora::capi::fatoora_InvoiceData_invoice_sub_type(this->AsFFI());
    return result;
}

inline diplomat::result<std::unique_ptr<fatoora::Party>, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::seller() const {
    auto result = fatoora::capi::fatoora_InvoiceData_seller(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Party>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Party>>(std::unique_ptr<fatoora::Party>(fatoora::Party::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Party>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Party>, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::buyer() const {
    auto result = fatoora::capi::fatoora_InvoiceData_buyer(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Party>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Party>>(std::unique_ptr<fatoora::Party>(fatoora::Party::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Party>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::InvoiceNote>, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::note() const {
    auto result = fatoora::capi::fatoora_InvoiceData_note(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::InvoiceNote>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::InvoiceNote>>(std::unique_ptr<fatoora::InvoiceNote>(fatoora::InvoiceNote::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::InvoiceNote>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline size_t fatoora::InvoiceData::line_items_len() const {
    auto result = fatoora::capi::fatoora_InvoiceData_line_items_len(this->AsFFI());
    return result;
}

inline diplomat::result<std::unique_ptr<fatoora::InvoiceLineItem>, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::line_item(size_t index) const {
    auto result = fatoora::capi::fatoora_InvoiceData_line_item(this->AsFFI(),
        index);
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::InvoiceLineItem>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::InvoiceLineItem>>(std::unique_ptr<fatoora::InvoiceLineItem>(fatoora::InvoiceLineItem::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::InvoiceLineItem>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::OriginalInvoiceRef>, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::original_invoice_ref() const {
    auto result = fatoora::capi::fatoora_InvoiceData_original_invoice_ref(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::OriginalInvoiceRef>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::OriginalInvoiceRef>>(std::unique_ptr<fatoora::OriginalInvoiceRef>(fatoora::OriginalInvoiceRef::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::OriginalInvoiceRef>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceData::original_invoice_reason() const {
    auto result = fatoora::capi::fatoora_InvoiceData_original_invoice_reason(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::InvoiceData* fatoora::InvoiceData::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::InvoiceData*>(this);
}

inline fatoora::capi::InvoiceData* fatoora::InvoiceData::AsFFI() {
    return reinterpret_cast<fatoora::capi::InvoiceData*>(this);
}

inline const fatoora::InvoiceData* fatoora::InvoiceData::FromFFI(const fatoora::capi::InvoiceData* ptr) {
    return reinterpret_cast<const fatoora::InvoiceData*>(ptr);
}

inline fatoora::InvoiceData* fatoora::InvoiceData::FromFFI(fatoora::capi::InvoiceData* ptr) {
    return reinterpret_cast<fatoora::InvoiceData*>(ptr);
}

inline void fatoora::InvoiceData::operator delete(void* ptr) {
    fatoora::capi::fatoora_InvoiceData_destroy(reinterpret_cast<fatoora::capi::InvoiceData*>(ptr));
}


#endif // fatoora_InvoiceData_HPP
