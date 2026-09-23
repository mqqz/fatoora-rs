#ifndef fatoora_Bytes_HPP
#define fatoora_Bytes_HPP

#include "Bytes.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "../diplomat_runtime.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    diplomat::capi::DiplomatU8View fatoora_Bytes_as_slice(const fatoora::capi::Bytes* self);

    void fatoora_Bytes_destroy(Bytes* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::span<const uint8_t> fatoora::Bytes::as_slice() const DIPLOMAT_LIFETIME_BOUND {
    auto result = fatoora::capi::fatoora_Bytes_as_slice(this->AsFFI());
    return diplomat::span<const uint8_t>(result.data, result.len);
}

inline const fatoora::capi::Bytes* fatoora::Bytes::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::Bytes*>(this);
}

inline fatoora::capi::Bytes* fatoora::Bytes::AsFFI() {
    return reinterpret_cast<fatoora::capi::Bytes*>(this);
}

inline const fatoora::Bytes* fatoora::Bytes::FromFFI(const fatoora::capi::Bytes* ptr) {
    return reinterpret_cast<const fatoora::Bytes*>(ptr);
}

inline fatoora::Bytes* fatoora::Bytes::FromFFI(fatoora::capi::Bytes* ptr) {
    return reinterpret_cast<fatoora::Bytes*>(ptr);
}

inline void fatoora::Bytes::operator delete(void* ptr) {
    fatoora::capi::fatoora_Bytes_destroy(reinterpret_cast<fatoora::capi::Bytes*>(ptr));
}


#endif // fatoora_Bytes_HPP
