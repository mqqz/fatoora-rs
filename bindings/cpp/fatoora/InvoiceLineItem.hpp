#ifndef fatoora_InvoiceLineItem_HPP
#define fatoora_InvoiceLineItem_HPP

#include "InvoiceLineItem.d.hpp"

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


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_InvoiceLineItem_description_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_description_result;
    fatoora_InvoiceLineItem_description_result fatoora_InvoiceLineItem_description(const fatoora::capi::InvoiceLineItem* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_unit_code_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_unit_code_result;
    fatoora_InvoiceLineItem_unit_code_result fatoora_InvoiceLineItem_unit_code(const fatoora::capi::InvoiceLineItem* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_quantity_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_quantity_result;
    fatoora_InvoiceLineItem_quantity_result fatoora_InvoiceLineItem_quantity(const fatoora::capi::InvoiceLineItem* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_unit_price_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_unit_price_result;
    fatoora_InvoiceLineItem_unit_price_result fatoora_InvoiceLineItem_unit_price(const fatoora::capi::InvoiceLineItem* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_total_amount_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_total_amount_result;
    fatoora_InvoiceLineItem_total_amount_result fatoora_InvoiceLineItem_total_amount(const fatoora::capi::InvoiceLineItem* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_vat_rate_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_vat_rate_result;
    fatoora_InvoiceLineItem_vat_rate_result fatoora_InvoiceLineItem_vat_rate(const fatoora::capi::InvoiceLineItem* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_vat_amount_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_vat_amount_result;
    fatoora_InvoiceLineItem_vat_amount_result fatoora_InvoiceLineItem_vat_amount(const fatoora::capi::InvoiceLineItem* self, diplomat::capi::DiplomatWrite* write);

    uint8_t fatoora_InvoiceLineItem_vat_category(const fatoora::capi::InvoiceLineItem* self);

    void fatoora_InvoiceLineItem_destroy(InvoiceLineItem* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::description() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_description(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::description_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_description(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::unit_code() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_unit_code(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::unit_code_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_unit_code(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::quantity() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_quantity(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::quantity_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_quantity(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::unit_price() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_unit_price(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::unit_price_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_unit_price(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::total_amount() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_total_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::total_amount_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_total_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::vat_rate() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_vat_rate(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::vat_rate_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_vat_rate(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::vat_amount() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_vat_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceLineItem::vat_amount_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceLineItem_vat_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline uint8_t fatoora::InvoiceLineItem::vat_category() const {
    auto result = fatoora::capi::fatoora_InvoiceLineItem_vat_category(this->AsFFI());
    return result;
}

inline const fatoora::capi::InvoiceLineItem* fatoora::InvoiceLineItem::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::InvoiceLineItem*>(this);
}

inline fatoora::capi::InvoiceLineItem* fatoora::InvoiceLineItem::AsFFI() {
    return reinterpret_cast<fatoora::capi::InvoiceLineItem*>(this);
}

inline const fatoora::InvoiceLineItem* fatoora::InvoiceLineItem::FromFFI(const fatoora::capi::InvoiceLineItem* ptr) {
    return reinterpret_cast<const fatoora::InvoiceLineItem*>(ptr);
}

inline fatoora::InvoiceLineItem* fatoora::InvoiceLineItem::FromFFI(fatoora::capi::InvoiceLineItem* ptr) {
    return reinterpret_cast<fatoora::InvoiceLineItem*>(ptr);
}

inline void fatoora::InvoiceLineItem::operator delete(void* ptr) {
    fatoora::capi::fatoora_InvoiceLineItem_destroy(reinterpret_cast<fatoora::capi::InvoiceLineItem*>(ptr));
}


#endif // fatoora_InvoiceLineItem_HPP
