#ifndef _NATIVE_CsidProduction_HPP
#define _NATIVE_CsidProduction_HPP

#include "CsidProduction.d.hpp"

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

    typedef struct fatoora_CsidProduction_create_result {union {_native::capi::CsidProduction* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsidProduction_create_result;
    fatoora_CsidProduction_create_result fatoora_CsidProduction_create(uint8_t environment, _native::diplomat::capi::OptionStringView request_id, _native::diplomat::capi::DiplomatStringView token, _native::diplomat::capi::DiplomatStringView secret);

    uint8_t fatoora_CsidProduction_env(const _native::capi::CsidProduction* self);

    typedef struct fatoora_CsidProduction_request_id_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsidProduction_request_id_result;
    fatoora_CsidProduction_request_id_result fatoora_CsidProduction_request_id(const _native::capi::CsidProduction* self);

    typedef struct fatoora_CsidProduction_binary_security_token_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsidProduction_binary_security_token_result;
    fatoora_CsidProduction_binary_security_token_result fatoora_CsidProduction_binary_security_token(const _native::capi::CsidProduction* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_CsidProduction_secret_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_CsidProduction_secret_result;
    fatoora_CsidProduction_secret_result fatoora_CsidProduction_secret(const _native::capi::CsidProduction* self, _native::diplomat::capi::DiplomatWrite* write);

    void fatoora_CsidProduction_destroy(CsidProduction* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::CsidProduction>, std::unique_ptr<_native::BindingError>> _native::CsidProduction::create(uint8_t environment, std::optional<std::string_view> request_id, std::string_view token, std::string_view secret) {
    auto result = _native::capi::fatoora_CsidProduction_create(environment,
        request_id.has_value() ? (_native::diplomat::capi::OptionStringView{ { {request_id.value().data(), request_id.value().size()} }, true }) : (_native::diplomat::capi::OptionStringView{ {}, false }),
        {token.data(), token.size()},
        {secret.data(), secret.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::CsidProduction>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::CsidProduction>>(std::unique_ptr<_native::CsidProduction>(_native::CsidProduction::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::CsidProduction>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline uint8_t _native::CsidProduction::env() const {
    auto result = _native::capi::fatoora_CsidProduction_env(this->AsFFI());
    return result;
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::CsidProduction::request_id() const {
    auto result = _native::capi::fatoora_CsidProduction_request_id(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::CsidProduction::binary_security_token() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_CsidProduction_binary_security_token(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::CsidProduction::binary_security_token_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_CsidProduction_binary_security_token(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::CsidProduction::secret() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_CsidProduction_secret(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::CsidProduction::secret_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_CsidProduction_secret(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::CsidProduction* _native::CsidProduction::AsFFI() const {
    return reinterpret_cast<const _native::capi::CsidProduction*>(this);
}

inline _native::capi::CsidProduction* _native::CsidProduction::AsFFI() {
    return reinterpret_cast<_native::capi::CsidProduction*>(this);
}

inline const _native::CsidProduction* _native::CsidProduction::FromFFI(const _native::capi::CsidProduction* ptr) {
    return reinterpret_cast<const _native::CsidProduction*>(ptr);
}

inline _native::CsidProduction* _native::CsidProduction::FromFFI(_native::capi::CsidProduction* ptr) {
    return reinterpret_cast<_native::CsidProduction*>(ptr);
}

inline void _native::CsidProduction::operator delete(void* ptr) {
    _native::capi::fatoora_CsidProduction_destroy(reinterpret_cast<_native::capi::CsidProduction*>(ptr));
}


#endif // _NATIVE_CsidProduction_HPP
