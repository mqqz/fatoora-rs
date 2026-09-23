#ifndef _NATIVE_BindingError_HPP
#define _NATIVE_BindingError_HPP

#include "BindingError.d.hpp"

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

    int32_t fatoora_BindingError_code(const _native::capi::BindingError* self);

    void fatoora_BindingError_message(const _native::capi::BindingError* self, _native::diplomat::capi::DiplomatWrite* write);

    void fatoora_BindingError_details_json(const _native::capi::BindingError* self, _native::diplomat::capi::DiplomatWrite* write);

    void fatoora_BindingError_destroy(BindingError* self);

    } // extern "C"
} // namespace capi
} // namespace

inline int32_t _native::BindingError::code() const {
    auto result = _native::capi::fatoora_BindingError_code(this->AsFFI());
    return result;
}

inline std::string _native::BindingError::message() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    _native::capi::fatoora_BindingError_message(this->AsFFI(),
        &write);
    return output;
}
template<typename W>
inline void _native::BindingError::message_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    _native::capi::fatoora_BindingError_message(this->AsFFI(),
        &write);
}

inline std::string _native::BindingError::details_json() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    _native::capi::fatoora_BindingError_details_json(this->AsFFI(),
        &write);
    return output;
}
template<typename W>
inline void _native::BindingError::details_json_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    _native::capi::fatoora_BindingError_details_json(this->AsFFI(),
        &write);
}

inline const _native::capi::BindingError* _native::BindingError::AsFFI() const {
    return reinterpret_cast<const _native::capi::BindingError*>(this);
}

inline _native::capi::BindingError* _native::BindingError::AsFFI() {
    return reinterpret_cast<_native::capi::BindingError*>(this);
}

inline const _native::BindingError* _native::BindingError::FromFFI(const _native::capi::BindingError* ptr) {
    return reinterpret_cast<const _native::BindingError*>(ptr);
}

inline _native::BindingError* _native::BindingError::FromFFI(_native::capi::BindingError* ptr) {
    return reinterpret_cast<_native::BindingError*>(ptr);
}

inline void _native::BindingError::operator delete(void* ptr) {
    _native::capi::fatoora_BindingError_destroy(reinterpret_cast<_native::capi::BindingError*>(ptr));
}


#endif // _NATIVE_BindingError_HPP
