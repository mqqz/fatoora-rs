#ifndef _NATIVE_SigningKey_HPP
#define _NATIVE_SigningKey_HPP

#include "SigningKey.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "BindingError.hpp"
#include "Bytes.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_SigningKey_generate_result {union {_native::capi::SigningKey* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_SigningKey_generate_result;
    fatoora_SigningKey_generate_result fatoora_SigningKey_generate(void);

    typedef struct fatoora_SigningKey_from_pem_result {union {_native::capi::SigningKey* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_SigningKey_from_pem_result;
    fatoora_SigningKey_from_pem_result fatoora_SigningKey_from_pem(_native::diplomat::capi::DiplomatStringView pem);

    typedef struct fatoora_SigningKey_from_der_result {union {_native::capi::SigningKey* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_SigningKey_from_der_result;
    fatoora_SigningKey_from_der_result fatoora_SigningKey_from_der(_native::diplomat::capi::DiplomatU8View der);

    typedef struct fatoora_SigningKey_to_pem_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SigningKey_to_pem_result;
    fatoora_SigningKey_to_pem_result fatoora_SigningKey_to_pem(const _native::capi::SigningKey* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SigningKey_to_der_result {union {_native::capi::Bytes* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_SigningKey_to_der_result;
    fatoora_SigningKey_to_der_result fatoora_SigningKey_to_der(const _native::capi::SigningKey* self);

    void fatoora_SigningKey_destroy(SigningKey* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>> _native::SigningKey::generate() {
    auto result = _native::capi::fatoora_SigningKey_generate();
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::SigningKey>>(std::unique_ptr<_native::SigningKey>(_native::SigningKey::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>> _native::SigningKey::from_pem(std::string_view pem) {
    auto result = _native::capi::fatoora_SigningKey_from_pem({pem.data(), pem.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::SigningKey>>(std::unique_ptr<_native::SigningKey>(_native::SigningKey::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>> _native::SigningKey::from_der(_native::diplomat::span<const uint8_t> der) {
    auto result = _native::capi::fatoora_SigningKey_from_der({der.data(), der.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::SigningKey>>(std::unique_ptr<_native::SigningKey>(_native::SigningKey::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SigningKey::to_pem() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SigningKey_to_pem(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SigningKey::to_pem_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SigningKey_to_pem(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>> _native::SigningKey::to_der() const {
    auto result = _native::capi::fatoora_SigningKey_to_der(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Bytes>>(std::unique_ptr<_native::Bytes>(_native::Bytes::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::SigningKey* _native::SigningKey::AsFFI() const {
    return reinterpret_cast<const _native::capi::SigningKey*>(this);
}

inline _native::capi::SigningKey* _native::SigningKey::AsFFI() {
    return reinterpret_cast<_native::capi::SigningKey*>(this);
}

inline const _native::SigningKey* _native::SigningKey::FromFFI(const _native::capi::SigningKey* ptr) {
    return reinterpret_cast<const _native::SigningKey*>(ptr);
}

inline _native::SigningKey* _native::SigningKey::FromFFI(_native::capi::SigningKey* ptr) {
    return reinterpret_cast<_native::SigningKey*>(ptr);
}

inline void _native::SigningKey::operator delete(void* ptr) {
    _native::capi::fatoora_SigningKey_destroy(reinterpret_cast<_native::capi::SigningKey*>(ptr));
}


#endif // _NATIVE_SigningKey_HPP
