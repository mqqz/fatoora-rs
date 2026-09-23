#ifndef _NATIVE_OtherId_HPP
#define _NATIVE_OtherId_HPP

#include "OtherId.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "BindingError.hpp"
#include "Text.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_OtherId_value_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_OtherId_value_result;
    fatoora_OtherId_value_result fatoora_OtherId_value(const _native::capi::OtherId* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_OtherId_scheme_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_OtherId_scheme_result;
    fatoora_OtherId_scheme_result fatoora_OtherId_scheme(const _native::capi::OtherId* self);

    void fatoora_OtherId_destroy(OtherId* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::OtherId::value() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_OtherId_value(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::OtherId::value_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_OtherId_value(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::OtherId::scheme() const {
    auto result = _native::capi::fatoora_OtherId_scheme(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::OtherId* _native::OtherId::AsFFI() const {
    return reinterpret_cast<const _native::capi::OtherId*>(this);
}

inline _native::capi::OtherId* _native::OtherId::AsFFI() {
    return reinterpret_cast<_native::capi::OtherId*>(this);
}

inline const _native::OtherId* _native::OtherId::FromFFI(const _native::capi::OtherId* ptr) {
    return reinterpret_cast<const _native::OtherId*>(ptr);
}

inline _native::OtherId* _native::OtherId::FromFFI(_native::capi::OtherId* ptr) {
    return reinterpret_cast<_native::OtherId*>(ptr);
}

inline void _native::OtherId::operator delete(void* ptr) {
    _native::capi::fatoora_OtherId_destroy(reinterpret_cast<_native::capi::OtherId*>(ptr));
}


#endif // _NATIVE_OtherId_HPP
