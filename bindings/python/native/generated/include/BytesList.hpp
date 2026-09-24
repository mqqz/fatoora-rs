#ifndef _NATIVE_BytesList_HPP
#define _NATIVE_BytesList_HPP

#include "BytesList.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "BindingError.hpp"
#include "Bytes.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    size_t fatoora_BytesList_len(const _native::capi::BytesList* self);

    bool fatoora_BytesList_is_empty(const _native::capi::BytesList* self);

    typedef struct fatoora_BytesList_get_result {union {_native::capi::Bytes* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_BytesList_get_result;
    fatoora_BytesList_get_result fatoora_BytesList_get(const _native::capi::BytesList* self, size_t index);

    void fatoora_BytesList_destroy(BytesList* self);

    } // extern "C"
} // namespace capi
} // namespace

inline size_t _native::BytesList::len() const {
    auto result = _native::capi::fatoora_BytesList_len(this->AsFFI());
    return result;
}

inline bool _native::BytesList::is_empty() const {
    auto result = _native::capi::fatoora_BytesList_is_empty(this->AsFFI());
    return result;
}

inline _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>> _native::BytesList::get(size_t index) const {
    auto result = _native::capi::fatoora_BytesList_get(this->AsFFI(),
        index);
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Bytes>>(std::unique_ptr<_native::Bytes>(_native::Bytes::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::BytesList* _native::BytesList::AsFFI() const {
    return reinterpret_cast<const _native::capi::BytesList*>(this);
}

inline _native::capi::BytesList* _native::BytesList::AsFFI() {
    return reinterpret_cast<_native::capi::BytesList*>(this);
}

inline const _native::BytesList* _native::BytesList::FromFFI(const _native::capi::BytesList* ptr) {
    return reinterpret_cast<const _native::BytesList*>(ptr);
}

inline _native::BytesList* _native::BytesList::FromFFI(_native::capi::BytesList* ptr) {
    return reinterpret_cast<_native::BytesList*>(ptr);
}

inline void _native::BytesList::operator delete(void* ptr) {
    _native::capi::fatoora_BytesList_destroy(reinterpret_cast<_native::capi::BytesList*>(ptr));
}


#endif // _NATIVE_BytesList_HPP
