#ifndef fatoora_VatId_HPP
#define fatoora_VatId_HPP

#include "VatId.d.hpp"

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


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_VatId_value_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_VatId_value_result;
    fatoora_VatId_value_result fatoora_VatId_value(const fatoora::capi::VatId* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_VatId_destroy(VatId* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::VatId::value() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_VatId_value(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::VatId::value_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_VatId_value(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::VatId* fatoora::VatId::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::VatId*>(this);
}

inline fatoora::capi::VatId* fatoora::VatId::AsFFI() {
    return reinterpret_cast<fatoora::capi::VatId*>(this);
}

inline const fatoora::VatId* fatoora::VatId::FromFFI(const fatoora::capi::VatId* ptr) {
    return reinterpret_cast<const fatoora::VatId*>(ptr);
}

inline fatoora::VatId* fatoora::VatId::FromFFI(fatoora::capi::VatId* ptr) {
    return reinterpret_cast<fatoora::VatId*>(ptr);
}

inline void fatoora::VatId::operator delete(void* ptr) {
    fatoora::capi::fatoora_VatId_destroy(reinterpret_cast<fatoora::capi::VatId*>(ptr));
}


#endif // fatoora_VatId_HPP
