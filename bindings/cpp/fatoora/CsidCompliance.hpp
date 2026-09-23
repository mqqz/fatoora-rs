#ifndef fatoora_CsidCompliance_HPP
#define fatoora_CsidCompliance_HPP

#include "CsidCompliance.d.hpp"

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
#include "Text.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_CsidCompliance_create_result {union {fatoora::capi::CsidCompliance* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_create_result;
    fatoora_CsidCompliance_create_result fatoora_CsidCompliance_create(uint8_t environment, diplomat::capi::OptionStringView request_id, diplomat::capi::DiplomatStringView token, diplomat::capi::DiplomatStringView secret);

    uint8_t fatoora_CsidCompliance_env(const fatoora::capi::CsidCompliance* self);

    typedef struct fatoora_CsidCompliance_request_id_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_request_id_result;
    fatoora_CsidCompliance_request_id_result fatoora_CsidCompliance_request_id(const fatoora::capi::CsidCompliance* self);

    typedef struct fatoora_CsidCompliance_binary_security_token_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_binary_security_token_result;
    fatoora_CsidCompliance_binary_security_token_result fatoora_CsidCompliance_binary_security_token(const fatoora::capi::CsidCompliance* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_CsidCompliance_secret_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_secret_result;
    fatoora_CsidCompliance_secret_result fatoora_CsidCompliance_secret(const fatoora::capi::CsidCompliance* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_CsidCompliance_destroy(CsidCompliance* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::CsidCompliance>, std::unique_ptr<fatoora::BindingError>> fatoora::CsidCompliance::create(uint8_t environment, std::optional<std::string_view> request_id, std::string_view token, std::string_view secret) {
    auto result = fatoora::capi::fatoora_CsidCompliance_create(environment,
        request_id.has_value() ? (diplomat::capi::OptionStringView{ { {request_id.value().data(), request_id.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }),
        {token.data(), token.size()},
        {secret.data(), secret.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::CsidCompliance>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::CsidCompliance>>(std::unique_ptr<fatoora::CsidCompliance>(fatoora::CsidCompliance::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::CsidCompliance>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline uint8_t fatoora::CsidCompliance::env() const {
    auto result = fatoora::capi::fatoora_CsidCompliance_env(this->AsFFI());
    return result;
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::CsidCompliance::request_id() const {
    auto result = fatoora::capi::fatoora_CsidCompliance_request_id(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::CsidCompliance::binary_security_token() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_CsidCompliance_binary_security_token(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::CsidCompliance::binary_security_token_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_CsidCompliance_binary_security_token(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::CsidCompliance::secret() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_CsidCompliance_secret(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::CsidCompliance::secret_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_CsidCompliance_secret(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::CsidCompliance* fatoora::CsidCompliance::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::CsidCompliance*>(this);
}

inline fatoora::capi::CsidCompliance* fatoora::CsidCompliance::AsFFI() {
    return reinterpret_cast<fatoora::capi::CsidCompliance*>(this);
}

inline const fatoora::CsidCompliance* fatoora::CsidCompliance::FromFFI(const fatoora::capi::CsidCompliance* ptr) {
    return reinterpret_cast<const fatoora::CsidCompliance*>(ptr);
}

inline fatoora::CsidCompliance* fatoora::CsidCompliance::FromFFI(fatoora::capi::CsidCompliance* ptr) {
    return reinterpret_cast<fatoora::CsidCompliance*>(ptr);
}

inline void fatoora::CsidCompliance::operator delete(void* ptr) {
    fatoora::capi::fatoora_CsidCompliance_destroy(reinterpret_cast<fatoora::capi::CsidCompliance*>(ptr));
}


#endif // fatoora_CsidCompliance_HPP
