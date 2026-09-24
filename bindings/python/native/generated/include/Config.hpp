#ifndef _NATIVE_Config_HPP
#define _NATIVE_Config_HPP

#include "Config.d.hpp"

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

    typedef struct fatoora_Config_new_result {union {_native::capi::Config* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Config_new_result;
    fatoora_Config_new_result fatoora_Config_new(uint8_t env);

    uint8_t fatoora_Config_env(const _native::capi::Config* self);

    void fatoora_Config_destroy(Config* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::Config>, std::unique_ptr<_native::BindingError>> _native::Config::new_(uint8_t env) {
    auto result = _native::capi::fatoora_Config_new(env);
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Config>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Config>>(std::unique_ptr<_native::Config>(_native::Config::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Config>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline uint8_t _native::Config::env() const {
    auto result = _native::capi::fatoora_Config_env(this->AsFFI());
    return result;
}

inline const _native::capi::Config* _native::Config::AsFFI() const {
    return reinterpret_cast<const _native::capi::Config*>(this);
}

inline _native::capi::Config* _native::Config::AsFFI() {
    return reinterpret_cast<_native::capi::Config*>(this);
}

inline const _native::Config* _native::Config::FromFFI(const _native::capi::Config* ptr) {
    return reinterpret_cast<const _native::Config*>(ptr);
}

inline _native::Config* _native::Config::FromFFI(_native::capi::Config* ptr) {
    return reinterpret_cast<_native::Config*>(ptr);
}

inline void _native::Config::operator delete(void* ptr) {
    _native::capi::fatoora_Config_destroy(reinterpret_cast<_native::capi::Config*>(ptr));
}


#endif // _NATIVE_Config_HPP
