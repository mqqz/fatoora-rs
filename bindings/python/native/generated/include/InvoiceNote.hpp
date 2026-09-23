#ifndef _NATIVE_InvoiceNote_HPP
#define _NATIVE_InvoiceNote_HPP

#include "InvoiceNote.d.hpp"

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

    typedef struct fatoora_InvoiceNote_language_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceNote_language_result;
    fatoora_InvoiceNote_language_result fatoora_InvoiceNote_language(const _native::capi::InvoiceNote* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceNote_text_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceNote_text_result;
    fatoora_InvoiceNote_text_result fatoora_InvoiceNote_text(const _native::capi::InvoiceNote* self, _native::diplomat::capi::DiplomatWrite* write);

    void fatoora_InvoiceNote_destroy(InvoiceNote* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceNote::language() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceNote_language(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceNote::language_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceNote_language(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::InvoiceNote::text() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_InvoiceNote_text(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::InvoiceNote::text_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_InvoiceNote_text(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::InvoiceNote* _native::InvoiceNote::AsFFI() const {
    return reinterpret_cast<const _native::capi::InvoiceNote*>(this);
}

inline _native::capi::InvoiceNote* _native::InvoiceNote::AsFFI() {
    return reinterpret_cast<_native::capi::InvoiceNote*>(this);
}

inline const _native::InvoiceNote* _native::InvoiceNote::FromFFI(const _native::capi::InvoiceNote* ptr) {
    return reinterpret_cast<const _native::InvoiceNote*>(ptr);
}

inline _native::InvoiceNote* _native::InvoiceNote::FromFFI(_native::capi::InvoiceNote* ptr) {
    return reinterpret_cast<_native::InvoiceNote*>(ptr);
}

inline void _native::InvoiceNote::operator delete(void* ptr) {
    _native::capi::fatoora_InvoiceNote_destroy(reinterpret_cast<_native::capi::InvoiceNote*>(ptr));
}


#endif // _NATIVE_InvoiceNote_HPP
