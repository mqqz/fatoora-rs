#ifndef _NATIVE_Csr_HPP
#define _NATIVE_Csr_HPP

#include "Csr.d.hpp"

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
#include "BytesList.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_Csr_from_der_result {union {_native::capi::Csr* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_from_der_result;
    fatoora_Csr_from_der_result fatoora_Csr_from_der(_native::diplomat::capi::DiplomatU8View der);

    typedef struct fatoora_Csr_to_der_result {union {_native::capi::Bytes* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_to_der_result;
    fatoora_Csr_to_der_result fatoora_Csr_to_der(const _native::capi::Csr* self);

    typedef struct fatoora_Csr_to_pem_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_to_pem_result;
    fatoora_Csr_to_pem_result fatoora_Csr_to_pem(const _native::capi::Csr* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Csr_to_base64_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_to_base64_result;
    fatoora_Csr_to_base64_result fatoora_Csr_to_base64(const _native::capi::Csr* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Csr_to_pem_base64_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_to_pem_base64_result;
    fatoora_Csr_to_pem_base64_result fatoora_Csr_to_pem_base64(const _native::capi::Csr* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Csr_subject_string_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_subject_string_result;
    fatoora_Csr_subject_string_result fatoora_Csr_subject_string(const _native::capi::Csr* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Csr_extension_values_der_result {union {_native::capi::BytesList* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_extension_values_der_result;
    fatoora_Csr_extension_values_der_result fatoora_Csr_extension_values_der(const _native::capi::Csr* self);

    void fatoora_Csr_destroy(Csr* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::Csr>, std::unique_ptr<_native::BindingError>> _native::Csr::from_der(_native::diplomat::span<const uint8_t> der) {
    auto result = _native::capi::fatoora_Csr_from_der({der.data(), der.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Csr>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Csr>>(std::unique_ptr<_native::Csr>(_native::Csr::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Csr>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>> _native::Csr::to_der() const {
    auto result = _native::capi::fatoora_Csr_to_der(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Bytes>>(std::unique_ptr<_native::Bytes>(_native::Bytes::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Csr::to_pem() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Csr_to_pem(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Csr::to_pem_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Csr_to_pem(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Csr::to_base64() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Csr_to_base64(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Csr::to_base64_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Csr_to_base64(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Csr::to_pem_base64() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Csr_to_pem_base64(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Csr::to_pem_base64_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Csr_to_pem_base64(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::Csr::subject_string() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_Csr_subject_string(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::Csr::subject_string_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_Csr_subject_string(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::BytesList>, std::unique_ptr<_native::BindingError>> _native::Csr::extension_values_der() const {
    auto result = _native::capi::fatoora_Csr_extension_values_der(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::BytesList>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::BytesList>>(std::unique_ptr<_native::BytesList>(_native::BytesList::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::BytesList>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::Csr* _native::Csr::AsFFI() const {
    return reinterpret_cast<const _native::capi::Csr*>(this);
}

inline _native::capi::Csr* _native::Csr::AsFFI() {
    return reinterpret_cast<_native::capi::Csr*>(this);
}

inline const _native::Csr* _native::Csr::FromFFI(const _native::capi::Csr* ptr) {
    return reinterpret_cast<const _native::Csr*>(ptr);
}

inline _native::Csr* _native::Csr::FromFFI(_native::capi::Csr* ptr) {
    return reinterpret_cast<_native::Csr*>(ptr);
}

inline void _native::Csr::operator delete(void* ptr) {
    _native::capi::fatoora_Csr_destroy(reinterpret_cast<_native::capi::Csr*>(ptr));
}


#endif // _NATIVE_Csr_HPP
