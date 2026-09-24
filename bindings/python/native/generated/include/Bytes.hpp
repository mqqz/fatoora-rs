#ifndef _NATIVE_Bytes_HPP
#define _NATIVE_Bytes_HPP

#include "Bytes.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    _native::diplomat::capi::DiplomatU8View fatoora_Bytes_as_slice(const _native::capi::Bytes* self);

    void fatoora_Bytes_destroy(Bytes* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::span<const uint8_t> _native::Bytes::as_slice() const DIPLOMAT_LIFETIME_BOUND {
    auto result = _native::capi::fatoora_Bytes_as_slice(this->AsFFI());
    return _native::diplomat::span<const uint8_t>(result.data, result.len);
}

inline const _native::capi::Bytes* _native::Bytes::AsFFI() const {
    return reinterpret_cast<const _native::capi::Bytes*>(this);
}

inline _native::capi::Bytes* _native::Bytes::AsFFI() {
    return reinterpret_cast<_native::capi::Bytes*>(this);
}

inline const _native::Bytes* _native::Bytes::FromFFI(const _native::capi::Bytes* ptr) {
    return reinterpret_cast<const _native::Bytes*>(ptr);
}

inline _native::Bytes* _native::Bytes::FromFFI(_native::capi::Bytes* ptr) {
    return reinterpret_cast<_native::Bytes*>(ptr);
}

inline void _native::Bytes::operator delete(void* ptr) {
    _native::capi::fatoora_Bytes_destroy(reinterpret_cast<_native::capi::Bytes*>(ptr));
}


#endif // _NATIVE_Bytes_HPP
