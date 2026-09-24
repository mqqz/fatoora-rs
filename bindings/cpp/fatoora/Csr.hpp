#ifndef fatoora_Csr_HPP
#define fatoora_Csr_HPP

#include "Csr.d.hpp"

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
#include "BytesList.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_Csr_from_der_result {union {fatoora::capi::Csr* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_from_der_result;
    fatoora_Csr_from_der_result fatoora_Csr_from_der(diplomat::capi::DiplomatU8View der);

    typedef struct fatoora_Csr_to_der_result {union {fatoora::capi::Bytes* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_to_der_result;
    fatoora_Csr_to_der_result fatoora_Csr_to_der(const fatoora::capi::Csr* self);

    typedef struct fatoora_Csr_to_pem_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_to_pem_result;
    fatoora_Csr_to_pem_result fatoora_Csr_to_pem(const fatoora::capi::Csr* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Csr_to_base64_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_to_base64_result;
    fatoora_Csr_to_base64_result fatoora_Csr_to_base64(const fatoora::capi::Csr* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Csr_to_pem_base64_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_to_pem_base64_result;
    fatoora_Csr_to_pem_base64_result fatoora_Csr_to_pem_base64(const fatoora::capi::Csr* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Csr_subject_string_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_subject_string_result;
    fatoora_Csr_subject_string_result fatoora_Csr_subject_string(const fatoora::capi::Csr* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Csr_extension_values_der_result {union {fatoora::capi::BytesList* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Csr_extension_values_der_result;
    fatoora_Csr_extension_values_der_result fatoora_Csr_extension_values_der(const fatoora::capi::Csr* self);

    void fatoora_Csr_destroy(Csr* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::Csr>, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::from_der(diplomat::span<const uint8_t> der) {
    auto result = fatoora::capi::fatoora_Csr_from_der({der.data(), der.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Csr>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Csr>>(std::unique_ptr<fatoora::Csr>(fatoora::Csr::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Csr>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::to_der() const {
    auto result = fatoora::capi::fatoora_Csr_to_der(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Bytes>>(std::unique_ptr<fatoora::Bytes>(fatoora::Bytes::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::to_pem() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Csr_to_pem(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::to_pem_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Csr_to_pem(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::to_base64() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Csr_to_base64(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::to_base64_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Csr_to_base64(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::to_pem_base64() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Csr_to_pem_base64(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::to_pem_base64_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Csr_to_pem_base64(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::subject_string() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Csr_subject_string(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::subject_string_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Csr_subject_string(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::BytesList>, std::unique_ptr<fatoora::BindingError>> fatoora::Csr::extension_values_der() const {
    auto result = fatoora::capi::fatoora_Csr_extension_values_der(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::BytesList>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::BytesList>>(std::unique_ptr<fatoora::BytesList>(fatoora::BytesList::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::BytesList>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::Csr* fatoora::Csr::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::Csr*>(this);
}

inline fatoora::capi::Csr* fatoora::Csr::AsFFI() {
    return reinterpret_cast<fatoora::capi::Csr*>(this);
}

inline const fatoora::Csr* fatoora::Csr::FromFFI(const fatoora::capi::Csr* ptr) {
    return reinterpret_cast<const fatoora::Csr*>(ptr);
}

inline fatoora::Csr* fatoora::Csr::FromFFI(fatoora::capi::Csr* ptr) {
    return reinterpret_cast<fatoora::Csr*>(ptr);
}

inline void fatoora::Csr::operator delete(void* ptr) {
    fatoora::capi::fatoora_Csr_destroy(reinterpret_cast<fatoora::capi::Csr*>(ptr));
}


#endif // fatoora_Csr_HPP
