#ifndef _NATIVE_FinalizedInvoice_HPP
#define _NATIVE_FinalizedInvoice_HPP

#include "FinalizedInvoice.d.hpp"

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
#include "diplomat_runtime.hpp"


namespace _native {
namespace capi {
    extern "C" {

    typedef struct fatoora_FinalizedInvoice_from_xml_result {union {_native::capi::FinalizedInvoice* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_from_xml_result;
    fatoora_FinalizedInvoice_from_xml_result fatoora_FinalizedInvoice_from_xml(_native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_FinalizedInvoice_from_file_result {union {_native::capi::FinalizedInvoice* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_from_file_result;
    fatoora_FinalizedInvoice_from_file_result fatoora_FinalizedInvoice_from_file(_native::diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_FinalizedInvoice_data_result {union {_native::capi::InvoiceData* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_data_result;
    fatoora_FinalizedInvoice_data_result fatoora_FinalizedInvoice_data(const _native::capi::FinalizedInvoice* self);

    typedef struct fatoora_FinalizedInvoice_totals_result {union {_native::capi::InvoiceTotals* ok; _native::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_totals_result;
    fatoora_FinalizedInvoice_totals_result fatoora_FinalizedInvoice_totals(const _native::capi::FinalizedInvoice* self);

    typedef struct fatoora_FinalizedInvoice_hash_base64_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_hash_base64_result;
    fatoora_FinalizedInvoice_hash_base64_result fatoora_FinalizedInvoice_hash_base64(const _native::capi::FinalizedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_FinalizedInvoice_xml_result {union { _native::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_xml_result;
    fatoora_FinalizedInvoice_xml_result fatoora_FinalizedInvoice_xml(const _native::capi::FinalizedInvoice* self, _native::diplomat::capi::DiplomatWrite* write);

    void fatoora_FinalizedInvoice_destroy(FinalizedInvoice* self);

    } // extern "C"
} // namespace capi
} // namespace

inline _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>> _native::FinalizedInvoice::from_xml(std::string_view value) {
    auto result = _native::capi::fatoora_FinalizedInvoice_from_xml({value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::FinalizedInvoice>>(std::unique_ptr<_native::FinalizedInvoice>(_native::FinalizedInvoice::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>> _native::FinalizedInvoice::from_file(std::string_view value) {
    auto result = _native::capi::fatoora_FinalizedInvoice_from_file({value.data(), value.size()});
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::FinalizedInvoice>>(std::unique_ptr<_native::FinalizedInvoice>(_native::FinalizedInvoice::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::InvoiceData>, std::unique_ptr<_native::BindingError>> _native::FinalizedInvoice::data() const {
    auto result = _native::capi::fatoora_FinalizedInvoice_data(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::InvoiceData>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::InvoiceData>>(std::unique_ptr<_native::InvoiceData>(_native::InvoiceData::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::InvoiceData>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::unique_ptr<_native::InvoiceTotals>, std::unique_ptr<_native::BindingError>> _native::FinalizedInvoice::totals() const {
    auto result = _native::capi::fatoora_FinalizedInvoice_totals(this->AsFFI());
    return result.is_ok ? _native::diplomat::result<std::unique_ptr<_native::InvoiceTotals>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::unique_ptr<_native::InvoiceTotals>>(std::unique_ptr<_native::InvoiceTotals>(_native::InvoiceTotals::FromFFI(result.ok)))) : _native::diplomat::result<std::unique_ptr<_native::InvoiceTotals>, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::FinalizedInvoice::hash_base64() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_FinalizedInvoice_hash_base64(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::FinalizedInvoice::hash_base64_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_FinalizedInvoice_hash_base64(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> _native::FinalizedInvoice::xml() const {
    std::string output;
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteFromString(output);
    auto result = _native::capi::fatoora_FinalizedInvoice_xml(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::string>(std::move(output))) : _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}
template<typename W>
inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> _native::FinalizedInvoice::xml_write(W& writeable) const {
    _native::diplomat::capi::DiplomatWrite write = _native::diplomat::WriteTrait<W>::Construct(writeable);
    auto result = _native::capi::fatoora_FinalizedInvoice_xml(this->AsFFI(),
        &write);
    return result.is_ok ? _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Ok<std::monostate>()) : _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>>(_native::diplomat::Err<std::unique_ptr<_native::BindingError>>(std::unique_ptr<_native::BindingError>(_native::BindingError::FromFFI(result.err))));
}

inline const _native::capi::FinalizedInvoice* _native::FinalizedInvoice::AsFFI() const {
    return reinterpret_cast<const _native::capi::FinalizedInvoice*>(this);
}

inline _native::capi::FinalizedInvoice* _native::FinalizedInvoice::AsFFI() {
    return reinterpret_cast<_native::capi::FinalizedInvoice*>(this);
}

inline const _native::FinalizedInvoice* _native::FinalizedInvoice::FromFFI(const _native::capi::FinalizedInvoice* ptr) {
    return reinterpret_cast<const _native::FinalizedInvoice*>(ptr);
}

inline _native::FinalizedInvoice* _native::FinalizedInvoice::FromFFI(_native::capi::FinalizedInvoice* ptr) {
    return reinterpret_cast<_native::FinalizedInvoice*>(ptr);
}

inline void _native::FinalizedInvoice::operator delete(void* ptr) {
    _native::capi::fatoora_FinalizedInvoice_destroy(reinterpret_cast<_native::capi::FinalizedInvoice*>(ptr));
}


#endif // _NATIVE_FinalizedInvoice_HPP
