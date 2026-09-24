#ifndef fatoora_CsidProduction_HPP
#define fatoora_CsidProduction_HPP

#include "CsidProduction.d.hpp"

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

    typedef struct fatoora_CsidProduction_create_result {union {fatoora::capi::CsidProduction* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsidProduction_create_result;
    fatoora_CsidProduction_create_result fatoora_CsidProduction_create(uint8_t environment, diplomat::capi::OptionStringView request_id, diplomat::capi::DiplomatStringView token, diplomat::capi::DiplomatStringView secret);

    uint8_t fatoora_CsidProduction_env(const fatoora::capi::CsidProduction* self);

    typedef struct fatoora_CsidProduction_request_id_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsidProduction_request_id_result;
    fatoora_CsidProduction_request_id_result fatoora_CsidProduction_request_id(const fatoora::capi::CsidProduction* self);

    typedef struct fatoora_CsidProduction_binary_security_token_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsidProduction_binary_security_token_result;
    fatoora_CsidProduction_binary_security_token_result fatoora_CsidProduction_binary_security_token(const fatoora::capi::CsidProduction* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_CsidProduction_secret_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_CsidProduction_secret_result;
    fatoora_CsidProduction_secret_result fatoora_CsidProduction_secret(const fatoora::capi::CsidProduction* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_CsidProduction_destroy(CsidProduction* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>> fatoora::CsidProduction::create(uint8_t environment, std::optional<std::string_view> request_id, std::string_view token, std::string_view secret) {
    auto result = fatoora::capi::fatoora_CsidProduction_create(environment,
        request_id.has_value() ? (diplomat::capi::OptionStringView{ { {request_id.value().data(), request_id.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }),
        {token.data(), token.size()},
        {secret.data(), secret.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::CsidProduction>>(std::unique_ptr<fatoora::CsidProduction>(fatoora::CsidProduction::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline uint8_t fatoora::CsidProduction::env() const {
    auto result = fatoora::capi::fatoora_CsidProduction_env(this->AsFFI());
    return result;
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::CsidProduction::request_id() const {
    auto result = fatoora::capi::fatoora_CsidProduction_request_id(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::CsidProduction::binary_security_token() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_CsidProduction_binary_security_token(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::CsidProduction::binary_security_token_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_CsidProduction_binary_security_token(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::CsidProduction::secret() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_CsidProduction_secret(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::CsidProduction::secret_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_CsidProduction_secret(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::CsidProduction* fatoora::CsidProduction::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::CsidProduction*>(this);
}

inline fatoora::capi::CsidProduction* fatoora::CsidProduction::AsFFI() {
    return reinterpret_cast<fatoora::capi::CsidProduction*>(this);
}

inline const fatoora::CsidProduction* fatoora::CsidProduction::FromFFI(const fatoora::capi::CsidProduction* ptr) {
    return reinterpret_cast<const fatoora::CsidProduction*>(ptr);
}

inline fatoora::CsidProduction* fatoora::CsidProduction::FromFFI(fatoora::capi::CsidProduction* ptr) {
    return reinterpret_cast<fatoora::CsidProduction*>(ptr);
}

inline void fatoora::CsidProduction::operator delete(void* ptr) {
    fatoora::capi::fatoora_CsidProduction_destroy(reinterpret_cast<fatoora::capi::CsidProduction*>(ptr));
}


#endif // fatoora_CsidProduction_HPP
