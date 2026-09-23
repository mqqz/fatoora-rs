#ifndef _NATIVE_SignedInvoice_HPP
#define _NATIVE_SignedInvoice_HPP

#include "SignedInvoice.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "BindingError.hpp"
#include "InvoiceData.hpp"
#include "InvoiceTotals.hpp"
#include "Text.hpp"
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_SignedInvoice_from_xml_result {union {_native::capi::SignedInvoice* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_from_xml_result;
    fatoora_SignedInvoice_from_xml_result fatoora_SignedInvoice_from_xml(_native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_SignedInvoice_from_file_result {union {_native::capi::SignedInvoice* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_from_file_result;
    fatoora_SignedInvoice_from_file_result fatoora_SignedInvoice_from_file(_native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_SignedInvoice_data_result {union {_native::capi::InvoiceData* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_data_result;
    fatoora_SignedInvoice_data_result fatoora_SignedInvoice_data(const _native::capi::SignedInvoice* self);

    typedef struct fatoora_SignedInvoice_totals_result {union {_native::capi::InvoiceTotals* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_totals_result;
    fatoora_SignedInvoice_totals_result fatoora_SignedInvoice_totals(const _native::capi::SignedInvoice* self);

    typedef struct fatoora_SignedInvoice_hash_base64_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_hash_base64_result;
    fatoora_SignedInvoice_hash_base64_result fatoora_SignedInvoice_hash_base64(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_xml_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_xml_result;
    fatoora_SignedInvoice_xml_result fatoora_SignedInvoice_xml(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_qr_code_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_qr_code_result;
    fatoora_SignedInvoice_qr_code_result fatoora_SignedInvoice_qr_code(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_signature_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_signature_result;
    fatoora_SignedInvoice_signature_result fatoora_SignedInvoice_signature(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_public_key_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_public_key_result;
    fatoora_SignedInvoice_public_key_result fatoora_SignedInvoice_public_key(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_invoice_hash_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_invoice_hash_result;
    fatoora_SignedInvoice_invoice_hash_result fatoora_SignedInvoice_invoice_hash(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_to_xml_base64_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_to_xml_base64_result;
    fatoora_SignedInvoice_to_xml_base64_result fatoora_SignedInvoice_to_xml_base64(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_issuer_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_issuer_result;
    fatoora_SignedInvoice_issuer_result fatoora_SignedInvoice_issuer(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_serial_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_serial_result;
    fatoora_SignedInvoice_serial_result fatoora_SignedInvoice_serial(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_cert_hash_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_cert_hash_result;
    fatoora_SignedInvoice_cert_hash_result fatoora_SignedInvoice_cert_hash(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_signed_props_hash_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_signed_props_hash_result;
    fatoora_SignedInvoice_signed_props_hash_result fatoora_SignedInvoice_signed_props_hash(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_signing_time_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_signing_time_result;
    fatoora_SignedInvoice_signing_time_result fatoora_SignedInvoice_signing_time(const _native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_SignedInvoice_zatca_key_signature_result {union {_native::capi::Text* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_zatca_key_signature_result;
    fatoora_SignedInvoice_zatca_key_signature_result fatoora_SignedInvoice_zatca_key_signature(const _native::capi::SignedInvoice* self);

    typedef struct fatoora_SignedInvoice_into_xml_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_SignedInvoice_into_xml_result;
    fatoora_SignedInvoice_into_xml_result fatoora_SignedInvoice_into_xml(_native::capi::SignedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    void fatoora_SignedInvoice_destroy(SignedInvoice* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::SignedInvoice>, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::from_xml(std::string_view value) {
    auto result = _native::capi::fatoora_SignedInvoice_from_xml({value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::SignedInvoice>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::SignedInvoice>>(std::unique_ptr<_native::SignedInvoice>(_native::SignedInvoice::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::SignedInvoice>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::SignedInvoice>, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::from_file(std::string_view value) {
    auto result = _native::capi::fatoora_SignedInvoice_from_file({value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::SignedInvoice>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::SignedInvoice>>(std::unique_ptr<_native::SignedInvoice>(_native::SignedInvoice::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::SignedInvoice>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::InvoiceData>, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::data() const {
    auto result = _native::capi::fatoora_SignedInvoice_data(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::InvoiceData>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::InvoiceData>>(std::unique_ptr<_native::InvoiceData>(_native::InvoiceData::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::InvoiceData>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::InvoiceTotals>, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::totals() const {
    auto result = _native::capi::fatoora_SignedInvoice_totals(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::InvoiceTotals>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::InvoiceTotals>>(std::unique_ptr<_native::InvoiceTotals>(_native::InvoiceTotals::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::InvoiceTotals>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::hash_base64() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_hash_base64(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::hash_base64_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_hash_base64(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::xml() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_xml(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::xml_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_xml(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::qr_code() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_qr_code(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::qr_code_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_qr_code(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::signature() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_signature(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::signature_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_signature(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::public_key() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_public_key(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::public_key_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_public_key(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::invoice_hash() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_invoice_hash(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::invoice_hash_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_invoice_hash(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::to_xml_base64() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_to_xml_base64(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::to_xml_base64_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_to_xml_base64(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::issuer() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_issuer(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::issuer_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_issuer(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::serial() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_serial(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::serial_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_serial(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::cert_hash() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_cert_hash(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::cert_hash_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_cert_hash(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::signed_props_hash() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_signed_props_hash(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::signed_props_hash_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_signed_props_hash(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::signing_time() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_signing_time(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::signing_time_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_signing_time(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::zatca_key_signature() const {
    auto result = _native::capi::fatoora_SignedInvoice_zatca_key_signature(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::Text>>(std::unique_ptr<_native::Text>(_native::Text::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::into_xml() {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_SignedInvoice_into_xml(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::SignedInvoice::into_xml_write(W& writeable) {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_SignedInvoice_into_xml(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::SignedInvoice* _native::SignedInvoice::AsFFI() const {
    return reinterpret_cast<const _native::capi::SignedInvoice*>(this);
}

inline _native::capi::SignedInvoice* _native::SignedInvoice::AsFFI() {
    return reinterpret_cast<_native::capi::SignedInvoice*>(this);
}

inline const _native::SignedInvoice* _native::SignedInvoice::FromFFI(const _native::capi::SignedInvoice* ptr) {
    return reinterpret_cast<const _native::SignedInvoice*>(ptr);
}

inline _native::SignedInvoice* _native::SignedInvoice::FromFFI(_native::capi::SignedInvoice* ptr) {
    return reinterpret_cast<_native::SignedInvoice*>(ptr);
}

inline void _native::SignedInvoice::operator delete(void* ptr) {
    _native::capi::fatoora_SignedInvoice_destroy(reinterpret_cast<_native::capi::SignedInvoice*>(ptr));
}


#endif // _NATIVE_SignedInvoice_HPP
