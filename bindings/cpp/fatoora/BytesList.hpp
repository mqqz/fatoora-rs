#ifndef fatoora_BytesList_HPP
#define fatoora_BytesList_HPP

#include "BytesList.d.hpp"

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
#include "Bytes.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    size_t fatoora_BytesList_len(const fatoora::capi::BytesList* self);

    bool fatoora_BytesList_is_empty(const fatoora::capi::BytesList* self);

    typedef struct fatoora_BytesList_get_result {union {fatoora::capi::Bytes* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_BytesList_get_result;
    fatoora_BytesList_get_result fatoora_BytesList_get(const fatoora::capi::BytesList* self, size_t index);

    void fatoora_BytesList_destroy(BytesList* self);

    } // extern "C"
} // namespace capi
} // namespace

inline size_t fatoora::BytesList::len() const {
    auto result = fatoora::capi::fatoora_BytesList_len(this->AsFFI());
    return result;
}

inline bool fatoora::BytesList::is_empty() const {
    auto result = fatoora::capi::fatoora_BytesList_is_empty(this->AsFFI());
    return result;
}

inline diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>> fatoora::BytesList::get(size_t index) const {
    auto result = fatoora::capi::fatoora_BytesList_get(this->AsFFI(),
        index);
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Bytes>>(std::unique_ptr<fatoora::Bytes>(fatoora::Bytes::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::BytesList* fatoora::BytesList::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::BytesList*>(this);
}

inline fatoora::capi::BytesList* fatoora::BytesList::AsFFI() {
    return reinterpret_cast<fatoora::capi::BytesList*>(this);
}

inline const fatoora::BytesList* fatoora::BytesList::FromFFI(const fatoora::capi::BytesList* ptr) {
    return reinterpret_cast<const fatoora::BytesList*>(ptr);
}

inline fatoora::BytesList* fatoora::BytesList::FromFFI(fatoora::capi::BytesList* ptr) {
    return reinterpret_cast<fatoora::BytesList*>(ptr);
}

inline void fatoora::BytesList::operator delete(void* ptr) {
    fatoora::capi::fatoora_BytesList_destroy(reinterpret_cast<fatoora::capi::BytesList*>(ptr));
}


#endif // fatoora_BytesList_HPP
