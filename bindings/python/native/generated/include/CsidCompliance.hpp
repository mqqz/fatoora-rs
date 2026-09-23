#ifndef _NATIVE_CsidCompliance_HPP
#define _NATIVE_CsidCompliance_HPP

#include "CsidCompliance.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "BindingError.hpp"
#include "Text.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_CsidCompliance_create_result {union {_native::capi::CsidCompliance* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_create_result;
    fatoora_CsidCompliance_create_result fatoora_CsidCompliance_create(uint8_t environment, _native::diplomat::capi::OptionStringView request_id, _native::diplomat::capi::DiplomatStringView token, _native::diplomat::capi::DiplomatStringView secret);

    uint8_t fatoora_CsidCompliance_env(const _native::capi::CsidCompliance* self);

    typedef struct fatoora_CsidCompliance_request_id_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_request_id_result;
    fatoora_CsidCompliance_request_id_result fatoora_CsidCompliance_request_id(const _native::capi::CsidCompliance* self);

    typedef struct fatoora_CsidCompliance_binary_security_token_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_binary_security_token_result;
    fatoora_CsidCompliance_binary_security_token_result fatoora_CsidCompliance_binary_security_token(const _native::capi::CsidCompliance* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_CsidCompliance_secret_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsidCompliance_secret_result;
    fatoora_CsidCompliance_secret_result fatoora_CsidCompliance_secret(const _native::capi::CsidCompliance* self, _native::diplomat::capi::DiplomatWrite* write);

    void fatoora_CsidCompliance_destroy(CsidCompliance* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::CsidCompliance>, std::unique_ptr<_native::BindingError>> _native::CsidCompliance::create(uint8_t environment, std::optional<std::string_view> request_id, std::string_view token, std::string_view secret) {
    auto result = _native::capi::fatoora_CsidCompliance_create(environment,
        request_id.has_value() ? (_native::diplomat::capi::OptionStringView{ { {request_id.value().data(), request_id.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        {token.data(), token.size()},
        {secret.data(), secret.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::CsidCompliance>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::CsidCompliance>>(std::unique_ptr<_native::CsidCompliance>(_native::CsidCompliance::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::CsidCompliance>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline uint8_t _native::CsidCompliance::env() const {
    auto result = _native::capi::fatoora_CsidCompliance_env(this->AsFFI());
    return result;
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::CsidCompliance::request_id() const {
    auto result = _native::capi::fatoora_CsidCompliance_request_id(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::CsidCompliance::binary_security_token() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_CsidCompliance_binary_security_token(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::CsidCompliance::binary_security_token_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_CsidCompliance_binary_security_token(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::CsidCompliance::secret() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_CsidCompliance_secret(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::CsidCompliance::secret_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_CsidCompliance_secret(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::CsidCompliance* _native::CsidCompliance::AsFFI() const {
    return reinterpret_cast<const _native::capi::CsidCompliance*>(this);
}

inline _native::capi::CsidCompliance* _native::CsidCompliance::AsFFI() {
    return reinterpret_cast<_native::capi::CsidCompliance*>(this);
}

inline const _native::CsidCompliance* _native::CsidCompliance::FromFFI(const _native::capi::CsidCompliance* ptr) {
    return reinterpret_cast<const _native::CsidCompliance*>(ptr);
}

inline _native::CsidCompliance* _native::CsidCompliance::FromFFI(_native::capi::CsidCompliance* ptr) {
    return reinterpret_cast<_native::CsidCompliance*>(ptr);
}

inline void _native::CsidCompliance::operator delete(void* ptr) {
    _native::capi::fatoora_CsidCompliance_destroy(reinterpret_cast<_native::capi::CsidCompliance*>(ptr));
}


#endif // _NATIVE_CsidCompliance_HPP
