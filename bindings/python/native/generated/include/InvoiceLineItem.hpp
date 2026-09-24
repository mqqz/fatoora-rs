#ifndef _NATIVE_InvoiceLineItem_HPP
#define _NATIVE_InvoiceLineItem_HPP

#include "InvoiceLineItem.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "BindingError.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_InvoiceLineItem_description_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_description_result;
    fatoora_InvoiceLineItem_description_result fatoora_InvoiceLineItem_description(const _native::capi::InvoiceLineItem* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_unit_code_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_unit_code_result;
    fatoora_InvoiceLineItem_unit_code_result fatoora_InvoiceLineItem_unit_code(const _native::capi::InvoiceLineItem* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_quantity_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_quantity_result;
    fatoora_InvoiceLineItem_quantity_result fatoora_InvoiceLineItem_quantity(const _native::capi::InvoiceLineItem* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_unit_price_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_unit_price_result;
    fatoora_InvoiceLineItem_unit_price_result fatoora_InvoiceLineItem_unit_price(const _native::capi::InvoiceLineItem* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_total_amount_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_total_amount_result;
    fatoora_InvoiceLineItem_total_amount_result fatoora_InvoiceLineItem_total_amount(const _native::capi::InvoiceLineItem* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_vat_rate_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_vat_rate_result;
    fatoora_InvoiceLineItem_vat_rate_result fatoora_InvoiceLineItem_vat_rate(const _native::capi::InvoiceLineItem* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceLineItem_vat_amount_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceLineItem_vat_amount_result;
    fatoora_InvoiceLineItem_vat_amount_result fatoora_InvoiceLineItem_vat_amount(const _native::capi::InvoiceLineItem* self, _native::diplomat::capi::DiplomatWrite* write);

    uint8_t fatoora_InvoiceLineItem_vat_category(const _native::capi::InvoiceLineItem* self);

    void fatoora_InvoiceLineItem_destroy(InvoiceLineItem* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::description() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceLineItem_description(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::description_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceLineItem_description(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::unit_code() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceLineItem_unit_code(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::unit_code_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceLineItem_unit_code(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::quantity() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceLineItem_quantity(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::quantity_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceLineItem_quantity(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::unit_price() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceLineItem_unit_price(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::unit_price_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceLineItem_unit_price(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::total_amount() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceLineItem_total_amount(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::total_amount_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceLineItem_total_amount(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::vat_rate() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceLineItem_vat_rate(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::vat_rate_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceLineItem_vat_rate(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::vat_amount() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceLineItem_vat_amount(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceLineItem::vat_amount_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceLineItem_vat_amount(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline uint8_t _native::InvoiceLineItem::vat_category() const {
    auto result = _native::capi::fatoora_InvoiceLineItem_vat_category(this->AsFFI());
    return result;
}

inline const _native::capi::InvoiceLineItem* _native::InvoiceLineItem::AsFFI() const {
    return reinterpret_cast<const _native::capi::InvoiceLineItem*>(this);
}

inline _native::capi::InvoiceLineItem* _native::InvoiceLineItem::AsFFI() {
    return reinterpret_cast<_native::capi::InvoiceLineItem*>(this);
}

inline const _native::InvoiceLineItem* _native::InvoiceLineItem::FromFFI(const _native::capi::InvoiceLineItem* ptr) {
    return reinterpret_cast<const _native::InvoiceLineItem*>(ptr);
}

inline _native::InvoiceLineItem* _native::InvoiceLineItem::FromFFI(_native::capi::InvoiceLineItem* ptr) {
    return reinterpret_cast<_native::InvoiceLineItem*>(ptr);
}

inline void _native::InvoiceLineItem::operator delete(void* ptr) {
    _native::capi::fatoora_InvoiceLineItem_destroy(reinterpret_cast<_native::capi::InvoiceLineItem*>(ptr));
}


#endif // _NATIVE_InvoiceLineItem_HPP
