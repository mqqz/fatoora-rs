#ifndef _NATIVE_Text_HPP
#define _NATIVE_Text_HPP

#include "Text.d.hpp"

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

    typedef struct fatoora_Text_value_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Text_value_result;
    fatoora_Text_value_result fatoora_Text_value(const _native::capi::Text* self, _native::diplomat::capi::DiplomatWrite* write);

    void fatoora_Text_destroy(Text* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Text::value() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Text_value(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Text::value_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Text_value(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::Text* _native::Text::AsFFI() const {
    return reinterpret_cast<const _native::capi::Text*>(this);
}

inline _native::capi::Text* _native::Text::AsFFI() {
    return reinterpret_cast<_native::capi::Text*>(this);
}

inline const _native::Text* _native::Text::FromFFI(const _native::capi::Text* ptr) {
    return reinterpret_cast<const _native::Text*>(ptr);
}

inline _native::Text* _native::Text::FromFFI(_native::capi::Text* ptr) {
    return reinterpret_cast<_native::Text*>(ptr);
}

inline void _native::Text::operator delete(void* ptr) {
    _native::capi::fatoora_Text_destroy(reinterpret_cast<_native::capi::Text*>(ptr));
}


#endif // _NATIVE_Text_HPP
