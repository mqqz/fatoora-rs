#ifndef fatoora_SignedInvoice_HPP
#define fatoora_SignedInvoice_HPP

#include "SignedInvoice.d.hpp"

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
#include "InvoiceData.hpp"
#include "InvoiceTotals.hpp"
#include "Text.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_SignedInvoice_from_xml_result {union {fatoora::capi::SignedInvoice* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_from_xml_result;
    fatoora_SignedInvoice_from_xml_result fatoora_SignedInvoice_from_xml(diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_SignedInvoice_from_file_result {union {fatoora::capi::SignedInvoice* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_from_file_result;
    fatoora_SignedInvoice_from_file_result fatoora_SignedInvoice_from_file(diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_SignedInvoice_data_result {union {fatoora::capi::InvoiceData* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_data_result;
    fatoora_SignedInvoice_data_result fatoora_SignedInvoice_data(const fatoora::capi::SignedInvoice* self);

    typedef struct fatoora_SignedInvoice_totals_result {union {fatoora::capi::InvoiceTotals* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_totals_result;
    fatoora_SignedInvoice_totals_result fatoora_SignedInvoice_totals(const fatoora::capi::SignedInvoice* self);

    typedef struct fatoora_SignedInvoice_hash_base64_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_hash_base64_result;
    fatoora_SignedInvoice_hash_base64_result fatoora_SignedInvoice_hash_base64(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_xml_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_xml_result;
    fatoora_SignedInvoice_xml_result fatoora_SignedInvoice_xml(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_qr_code_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_qr_code_result;
    fatoora_SignedInvoice_qr_code_result fatoora_SignedInvoice_qr_code(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_signature_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_signature_result;
    fatoora_SignedInvoice_signature_result fatoora_SignedInvoice_signature(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_public_key_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_public_key_result;
    fatoora_SignedInvoice_public_key_result fatoora_SignedInvoice_public_key(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_invoice_hash_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_invoice_hash_result;
    fatoora_SignedInvoice_invoice_hash_result fatoora_SignedInvoice_invoice_hash(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_to_xml_base64_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_to_xml_base64_result;
    fatoora_SignedInvoice_to_xml_base64_result fatoora_SignedInvoice_to_xml_base64(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_issuer_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_issuer_result;
    fatoora_SignedInvoice_issuer_result fatoora_SignedInvoice_issuer(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_serial_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_serial_result;
    fatoora_SignedInvoice_serial_result fatoora_SignedInvoice_serial(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_cert_hash_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_cert_hash_result;
    fatoora_SignedInvoice_cert_hash_result fatoora_SignedInvoice_cert_hash(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_signed_props_hash_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_signed_props_hash_result;
    fatoora_SignedInvoice_signed_props_hash_result fatoora_SignedInvoice_signed_props_hash(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_signing_time_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_signing_time_result;
    fatoora_SignedInvoice_signing_time_result fatoora_SignedInvoice_signing_time(const fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_zatca_key_signature_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_zatca_key_signature_result;
    fatoora_SignedInvoice_zatca_key_signature_result fatoora_SignedInvoice_zatca_key_signature(const fatoora::capi::SignedInvoice* self);

    typedef struct fatoora_SignedInvoice_into_xml_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_into_xml_result;
    fatoora_SignedInvoice_into_xml_result fatoora_SignedInvoice_into_xml(fatoora::capi::SignedInvoice* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_SignedInvoice_destroy(SignedInvoice* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::from_xml(std::string_view value) {
    auto result = fatoora::capi::fatoora_SignedInvoice_from_xml({value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::SignedInvoice>>(std::unique_ptr<fatoora::SignedInvoice>(fatoora::SignedInvoice::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::from_file(std::string_view value) {
    auto result = fatoora::capi::fatoora_SignedInvoice_from_file({value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::SignedInvoice>>(std::unique_ptr<fatoora::SignedInvoice>(fatoora::SignedInvoice::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::InvoiceData>, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::data() const {
    auto result = fatoora::capi::fatoora_SignedInvoice_data(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::InvoiceData>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::InvoiceData>>(std::unique_ptr<fatoora::InvoiceData>(fatoora::InvoiceData::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::InvoiceData>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::InvoiceTotals>, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::totals() const {
    auto result = fatoora::capi::fatoora_SignedInvoice_totals(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::InvoiceTotals>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::InvoiceTotals>>(std::unique_ptr<fatoora::InvoiceTotals>(fatoora::InvoiceTotals::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::InvoiceTotals>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::hash_base64() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_hash_base64(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::hash_base64_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_hash_base64(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::xml() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_xml(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::xml_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_xml(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::qr_code() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_qr_code(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::qr_code_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_qr_code(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::signature() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_signature(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::signature_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_signature(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::public_key() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_public_key(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::public_key_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_public_key(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::invoice_hash() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_invoice_hash(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::invoice_hash_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_invoice_hash(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::to_xml_base64() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_to_xml_base64(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::to_xml_base64_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_to_xml_base64(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::issuer() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_issuer(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::issuer_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_issuer(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::serial() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_serial(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::serial_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_serial(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::cert_hash() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_cert_hash(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::cert_hash_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_cert_hash(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::signed_props_hash() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_signed_props_hash(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::signed_props_hash_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_signed_props_hash(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::signing_time() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_signing_time(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::signing_time_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_signing_time(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::zatca_key_signature() const {
    auto result = fatoora::capi::fatoora_SignedInvoice_zatca_key_signature(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::into_xml() {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_SignedInvoice_into_xml(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::SignedInvoice::into_xml_write(W& writeable) {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_SignedInvoice_into_xml(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::SignedInvoice* fatoora::SignedInvoice::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::SignedInvoice*>(this);
}

inline fatoora::capi::SignedInvoice* fatoora::SignedInvoice::AsFFI() {
    return reinterpret_cast<fatoora::capi::SignedInvoice*>(this);
}

inline const fatoora::SignedInvoice* fatoora::SignedInvoice::FromFFI(const fatoora::capi::SignedInvoice* ptr) {
    return reinterpret_cast<const fatoora::SignedInvoice*>(ptr);
}

inline fatoora::SignedInvoice* fatoora::SignedInvoice::FromFFI(fatoora::capi::SignedInvoice* ptr) {
    return reinterpret_cast<fatoora::SignedInvoice*>(ptr);
}

inline void fatoora::SignedInvoice::operator delete(void* ptr) {
    fatoora::capi::fatoora_SignedInvoice_destroy(reinterpret_cast<fatoora::capi::SignedInvoice*>(ptr));
}


#endif // fatoora_SignedInvoice_HPP
