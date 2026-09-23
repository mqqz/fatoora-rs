#ifndef fatoora_Signer_HPP
#define fatoora_Signer_HPP

#include "Signer.d.hpp"

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
#include "FinalizedInvoice.hpp"
#include "SignedInvoice.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_Signer_from_pem_result {union {fatoora::capi::Signer* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Signer_from_pem_result;
    fatoora_Signer_from_pem_result fatoora_Signer_from_pem(diplomat::capi::DiplomatStringView cert_pem, diplomat::capi::DiplomatStringView key_pem);

    typedef struct fatoora_Signer_from_der_result {union {fatoora::capi::Signer* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Signer_from_der_result;
    fatoora_Signer_from_der_result fatoora_Signer_from_der(diplomat::capi::DiplomatU8View cert_der, diplomat::capi::DiplomatU8View key_der);

    typedef struct fatoora_Signer_certificate_der_result {union {fatoora::capi::Bytes* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Signer_certificate_der_result;
    fatoora_Signer_certificate_der_result fatoora_Signer_certificate_der(const fatoora::capi::Signer* self);

    typedef struct fatoora_Signer_certificate_pem_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Signer_certificate_pem_result;
    fatoora_Signer_certificate_pem_result fatoora_Signer_certificate_pem(const fatoora::capi::Signer* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_Signer_sign_result {union {fatoora::capi::SignedInvoice* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Signer_sign_result;
    fatoora_Signer_sign_result fatoora_Signer_sign(const fatoora::capi::Signer* self, fatoora::capi::FinalizedInvoice* invoice);

    typedef struct fatoora_Signer_sign_xml_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_Signer_sign_xml_result;
    fatoora_Signer_sign_xml_result fatoora_Signer_sign_xml(const fatoora::capi::Signer* self, diplomat::capi::DiplomatStringView xml, diplomat::capi::DiplomatWrite* write);

    void fatoora_Signer_destroy(Signer* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::Signer>, std::unique_ptr<fatoora::BindingError>> fatoora::Signer::from_pem(std::string_view cert_pem, std::string_view key_pem) {
    auto result = fatoora::capi::fatoora_Signer_from_pem({cert_pem.data(), cert_pem.size()},
        {key_pem.data(), key_pem.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Signer>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Signer>>(std::unique_ptr<fatoora::Signer>(fatoora::Signer::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Signer>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Signer>, std::unique_ptr<fatoora::BindingError>> fatoora::Signer::from_der(diplomat::span<const uint8_t> cert_der, diplomat::span<const uint8_t> key_der) {
    auto result = fatoora::capi::fatoora_Signer_from_der({cert_der.data(), cert_der.size()},
        {key_der.data(), key_der.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Signer>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Signer>>(std::unique_ptr<fatoora::Signer>(fatoora::Signer::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Signer>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>> fatoora::Signer::certificate_der() const {
    auto result = fatoora::capi::fatoora_Signer_certificate_der(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Bytes>>(std::unique_ptr<fatoora::Bytes>(fatoora::Bytes::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Signer::certificate_pem() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Signer_certificate_pem(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Signer::certificate_pem_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Signer_certificate_pem(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>> fatoora::Signer::sign(fatoora::FinalizedInvoice& invoice) const {
    auto result = fatoora::capi::fatoora_Signer_sign(this->AsFFI(),
        invoice.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::SignedInvoice>>(std::unique_ptr<fatoora::SignedInvoice>(fatoora::SignedInvoice::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::Signer::sign_xml(std::string_view xml) const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_Signer_sign_xml(this->AsFFI(),
        {xml.data(), xml.size()},
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::Signer::sign_xml_write(std::string_view xml, W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_Signer_sign_xml(this->AsFFI(),
        {xml.data(), xml.size()},
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::Signer* fatoora::Signer::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::Signer*>(this);
}

inline fatoora::capi::Signer* fatoora::Signer::AsFFI() {
    return reinterpret_cast<fatoora::capi::Signer*>(this);
}

inline const fatoora::Signer* fatoora::Signer::FromFFI(const fatoora::capi::Signer* ptr) {
    return reinterpret_cast<const fatoora::Signer*>(ptr);
}

inline fatoora::Signer* fatoora::Signer::FromFFI(fatoora::capi::Signer* ptr) {
    return reinterpret_cast<fatoora::Signer*>(ptr);
}

inline void fatoora::Signer::operator delete(void* ptr) {
    fatoora::capi::fatoora_Signer_destroy(reinterpret_cast<fatoora::capi::Signer*>(ptr));
}


#endif // fatoora_Signer_HPP
