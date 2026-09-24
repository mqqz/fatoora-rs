#ifndef fatoora_SigningKey_HPP
#define fatoora_SigningKey_HPP

#include "SigningKey.d.hpp"

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

    typedef struct fatoora_SigningKey_generate_result {union {fatoora::capi::SigningKey* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SigningKey_generate_result;
    fatoora_SigningKey_generate_result fatoora_SigningKey_generate(void);

    typedef struct fatoora_SigningKey_from_pem_result {union {fatoora::capi::SigningKey* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SigningKey_from_pem_result;
    fatoora_SigningKey_from_pem_result fatoora_SigningKey_from_pem(diplomat::capi::DiplomatStringView pem);

    typedef struct fatoora_SigningKey_from_der_result {union {fatoora::capi::SigningKey* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SigningKey_from_der_result;
    fatoora_SigningKey_from_der_result fatoora_SigningKey_from_der(diplomat::capi::DiplomatU8View der);

    typedef struct fatoora_SigningKey_to_pem_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SigningKey_to_pem_result;
    fatoora_SigningKey_to_pem_result fatoora_SigningKey_to_pem(const fatoora::capi::SigningKey* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SigningKey_to_der_result {union {fatoora::capi::Bytes* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SigningKey_to_der_result;
    fatoora_SigningKey_to_der_result fatoora_SigningKey_to_der(const fatoora::capi::SigningKey* self);

    void fatoora_SigningKey_destroy(SigningKey* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>> fatoora::SigningKey::generate() {
    auto result = fatoora::capi::fatoora_SigningKey_generate();
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::SigningKey>>(std::unique_ptr<fatoora::SigningKey>(fatoora::SigningKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>> fatoora::SigningKey::from_pem(std::string_view pem) {
    auto result = fatoora::capi::fatoora_SigningKey_from_pem({pem.data(), pem.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::SigningKey>>(std::unique_ptr<fatoora::SigningKey>(fatoora::SigningKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>> fatoora::SigningKey::from_der(diplomat::span<const uint8_t> der) {
    auto result = fatoora::capi::fatoora_SigningKey_from_der({der.data(), der.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::SigningKey>>(std::unique_ptr<fatoora::SigningKey>(fatoora::SigningKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SigningKey::to_pem() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SigningKey_to_pem(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SigningKey::to_pem_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SigningKey_to_pem(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>> fatoora::SigningKey::to_der() const {
    auto result = fatoora::capi::fatoora_SigningKey_to_der(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Bytes>>(std::unique_ptr<fatoora::Bytes>(fatoora::Bytes::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::SigningKey* fatoora::SigningKey::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::SigningKey*>(this);
}

inline fatoora::capi::SigningKey* fatoora::SigningKey::AsFFI() {
    return reinterpret_cast<fatoora::capi::SigningKey*>(this);
}

inline const fatoora::SigningKey* fatoora::SigningKey::FromFFI(const fatoora::capi::SigningKey* ptr) {
    return reinterpret_cast<const fatoora::SigningKey*>(ptr);
}

inline fatoora::SigningKey* fatoora::SigningKey::FromFFI(fatoora::capi::SigningKey* ptr) {
    return reinterpret_cast<fatoora::SigningKey*>(ptr);
}

inline void fatoora::SigningKey::operator delete(void* ptr) {
    fatoora::capi::fatoora_SigningKey_destroy(reinterpret_cast<fatoora::capi::SigningKey*>(ptr));
}


#endif // fatoora_SigningKey_HPP
