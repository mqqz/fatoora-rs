#ifndef fatoora_BindingError_HPP
#define fatoora_BindingError_HPP

#include "BindingError.d.hpp"

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

    int32_t fatoora_BindingError_code(const fatoora::capi::BindingError* self);

    void fatoora_BindingError_message(const fatoora::capi::BindingError* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_BindingError_details_json(const fatoora::capi::BindingError* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_BindingError_destroy(BindingError* self);

    } // extern "C"
} // namespace capi
} // namespace

inline int32_t fatoora::BindingError::code() const {
    auto result = fatoora::capi::fatoora_BindingError_code(this->AsFFI());
    return result;
}

inline std::string fatoora::BindingError::message() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    fatoora::capi::fatoora_BindingError_message(this->AsFFI(),
        &write);
    return output;
}
template<typename W>
inline void fatoora::BindingError::message_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    fatoora::capi::fatoora_BindingError_message(this->AsFFI(),
        &write);
}

inline std::string fatoora::BindingError::details_json() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    fatoora::capi::fatoora_BindingError_details_json(this->AsFFI(),
        &write);
    return output;
}
template<typename W>
inline void fatoora::BindingError::details_json_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    fatoora::capi::fatoora_BindingError_details_json(this->AsFFI(),
        &write);
}

inline const fatoora::capi::BindingError* fatoora::BindingError::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::BindingError*>(this);
}

inline fatoora::capi::BindingError* fatoora::BindingError::AsFFI() {
    return reinterpret_cast<fatoora::capi::BindingError*>(this);
}

inline const fatoora::BindingError* fatoora::BindingError::FromFFI(const fatoora::capi::BindingError* ptr) {
    return reinterpret_cast<const fatoora::BindingError*>(ptr);
}

inline fatoora::BindingError* fatoora::BindingError::FromFFI(fatoora::capi::BindingError* ptr) {
    return reinterpret_cast<fatoora::BindingError*>(ptr);
}

inline void fatoora::BindingError::operator delete(void* ptr) {
    fatoora::capi::fatoora_BindingError_destroy(reinterpret_cast<fatoora::capi::BindingError*>(ptr));
}


#endif // fatoora_BindingError_HPP
