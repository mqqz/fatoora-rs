#ifndef fatoora_FinalizedInvoice_HPP
#define fatoora_FinalizedInvoice_HPP

#include "FinalizedInvoice.d.hpp"

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


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_FinalizedInvoice_from_xml_result {union {fatoora::capi::FinalizedInvoice* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_from_xml_result;
    fatoora_FinalizedInvoice_from_xml_result fatoora_FinalizedInvoice_from_xml(diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_FinalizedInvoice_from_file_result {union {fatoora::capi::FinalizedInvoice* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_from_file_result;
    fatoora_FinalizedInvoice_from_file_result fatoora_FinalizedInvoice_from_file(diplomat::capi::DiplomatStringView value);

    typedef struct fatoora_FinalizedInvoice_data_result {union {fatoora::capi::InvoiceData* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_data_result;
    fatoora_FinalizedInvoice_data_result fatoora_FinalizedInvoice_data(const fatoora::capi::FinalizedInvoice* self);

    typedef struct fatoora_FinalizedInvoice_totals_result {union {fatoora::capi::InvoiceTotals* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_totals_result;
    fatoora_FinalizedInvoice_totals_result fatoora_FinalizedInvoice_totals(const fatoora::capi::FinalizedInvoice* self);

    typedef struct fatoora_FinalizedInvoice_hash_base64_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_hash_base64_result;
    fatoora_FinalizedInvoice_hash_base64_result fatoora_FinalizedInvoice_hash_base64(const fatoora::capi::FinalizedInvoice* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_FinalizedInvoice_xml_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_FinalizedInvoice_xml_result;
    fatoora_FinalizedInvoice_xml_result fatoora_FinalizedInvoice_xml(const fatoora::capi::FinalizedInvoice* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_FinalizedInvoice_destroy(FinalizedInvoice* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>> fatoora::FinalizedInvoice::from_xml(std::string_view value) {
    auto result = fatoora::capi::fatoora_FinalizedInvoice_from_xml({value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::FinalizedInvoice>>(std::unique_ptr<fatoora::FinalizedInvoice>(fatoora::FinalizedInvoice::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>> fatoora::FinalizedInvoice::from_file(std::string_view value) {
    auto result = fatoora::capi::fatoora_FinalizedInvoice_from_file({value.data(), value.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::FinalizedInvoice>>(std::unique_ptr<fatoora::FinalizedInvoice>(fatoora::FinalizedInvoice::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::InvoiceData>, std::unique_ptr<fatoora::BindingError>> fatoora::FinalizedInvoice::data() const {
    auto result = fatoora::capi::fatoora_FinalizedInvoice_data(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::InvoiceData>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::InvoiceData>>(std::unique_ptr<fatoora::InvoiceData>(fatoora::InvoiceData::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::InvoiceData>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::InvoiceTotals>, std::unique_ptr<fatoora::BindingError>> fatoora::FinalizedInvoice::totals() const {
    auto result = fatoora::capi::fatoora_FinalizedInvoice_totals(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::InvoiceTotals>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::InvoiceTotals>>(std::unique_ptr<fatoora::InvoiceTotals>(fatoora::InvoiceTotals::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::InvoiceTotals>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::FinalizedInvoice::hash_base64() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_FinalizedInvoice_hash_base64(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::FinalizedInvoice::hash_base64_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_FinalizedInvoice_hash_base64(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::FinalizedInvoice::xml() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_FinalizedInvoice_xml(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::FinalizedInvoice::xml_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_FinalizedInvoice_xml(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::FinalizedInvoice* fatoora::FinalizedInvoice::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::FinalizedInvoice*>(this);
}

inline fatoora::capi::FinalizedInvoice* fatoora::FinalizedInvoice::AsFFI() {
    return reinterpret_cast<fatoora::capi::FinalizedInvoice*>(this);
}

inline const fatoora::FinalizedInvoice* fatoora::FinalizedInvoice::FromFFI(const fatoora::capi::FinalizedInvoice* ptr) {
    return reinterpret_cast<const fatoora::FinalizedInvoice*>(ptr);
}

inline fatoora::FinalizedInvoice* fatoora::FinalizedInvoice::FromFFI(fatoora::capi::FinalizedInvoice* ptr) {
    return reinterpret_cast<fatoora::FinalizedInvoice*>(ptr);
}

inline void fatoora::FinalizedInvoice::operator delete(void* ptr) {
    fatoora::capi::fatoora_FinalizedInvoice_destroy(reinterpret_cast<fatoora::capi::FinalizedInvoice*>(ptr));
}


#endif // fatoora_FinalizedInvoice_HPP
