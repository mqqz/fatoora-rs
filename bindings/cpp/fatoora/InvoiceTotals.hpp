#ifndef fatoora_InvoiceTotals_HPP
#define fatoora_InvoiceTotals_HPP

#include "InvoiceTotals.d.hpp"

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


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_InvoiceTotals_tax_inclusive_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_tax_inclusive_result;
    fatoora_InvoiceTotals_tax_inclusive_result fatoora_InvoiceTotals_tax_inclusive(const fatoora::capi::InvoiceTotals* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceTotals_tax_amount_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_tax_amount_result;
    fatoora_InvoiceTotals_tax_amount_result fatoora_InvoiceTotals_tax_amount(const fatoora::capi::InvoiceTotals* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceTotals_line_extension_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_line_extension_result;
    fatoora_InvoiceTotals_line_extension_result fatoora_InvoiceTotals_line_extension(const fatoora::capi::InvoiceTotals* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceTotals_allowance_total_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_allowance_total_result;
    fatoora_InvoiceTotals_allowance_total_result fatoora_InvoiceTotals_allowance_total(const fatoora::capi::InvoiceTotals* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceTotals_charge_total_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_charge_total_result;
    fatoora_InvoiceTotals_charge_total_result fatoora_InvoiceTotals_charge_total(const fatoora::capi::InvoiceTotals* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceTotals_taxable_amount_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_taxable_amount_result;
    fatoora_InvoiceTotals_taxable_amount_result fatoora_InvoiceTotals_taxable_amount(const fatoora::capi::InvoiceTotals* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceTotals_prepaid_amount_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_prepaid_amount_result;
    fatoora_InvoiceTotals_prepaid_amount_result fatoora_InvoiceTotals_prepaid_amount(const fatoora::capi::InvoiceTotals* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceTotals_payable_rounding_amount_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_payable_rounding_amount_result;
    fatoora_InvoiceTotals_payable_rounding_amount_result fatoora_InvoiceTotals_payable_rounding_amount(const fatoora::capi::InvoiceTotals* self, diplomat::capi::DiplomatWrite* write);

    typedef struct fatoora_InvoiceTotals_payable_amount_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_InvoiceTotals_payable_amount_result;
    fatoora_InvoiceTotals_payable_amount_result fatoora_InvoiceTotals_payable_amount(const fatoora::capi::InvoiceTotals* self, diplomat::capi::DiplomatWrite* write);

    void fatoora_InvoiceTotals_destroy(InvoiceTotals* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::tax_inclusive() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceTotals_tax_inclusive(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::tax_inclusive_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceTotals_tax_inclusive(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::tax_amount() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceTotals_tax_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::tax_amount_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceTotals_tax_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::line_extension() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceTotals_line_extension(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::line_extension_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceTotals_line_extension(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::allowance_total() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceTotals_allowance_total(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::allowance_total_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceTotals_allowance_total(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::charge_total() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceTotals_charge_total(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::charge_total_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceTotals_charge_total(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::taxable_amount() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceTotals_taxable_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::taxable_amount_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceTotals_taxable_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::prepaid_amount() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceTotals_prepaid_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::prepaid_amount_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceTotals_prepaid_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::payable_rounding_amount() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceTotals_payable_rounding_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::payable_rounding_amount_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceTotals_payable_rounding_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::payable_amount() const {
    std::string output;
    diplomat::capi::DiplomatWrite write = diplomat::WriteFromString(output);
    auto result = fatoora::capi::fatoora_InvoiceTotals_payable_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::string>(std::move(output))) : diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}
template<typename W>
inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::InvoiceTotals::payable_amount_write(W& writeable) const {
    diplomat::capi::DiplomatWrite write = diplomat::WriteTrait<W>::Construct(writeable);
    auto result = fatoora::capi::fatoora_InvoiceTotals_payable_amount(this->AsFFI(),
        &write);
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::InvoiceTotals* fatoora::InvoiceTotals::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::InvoiceTotals*>(this);
}

inline fatoora::capi::InvoiceTotals* fatoora::InvoiceTotals::AsFFI() {
    return reinterpret_cast<fatoora::capi::InvoiceTotals*>(this);
}

inline const fatoora::InvoiceTotals* fatoora::InvoiceTotals::FromFFI(const fatoora::capi::InvoiceTotals* ptr) {
    return reinterpret_cast<const fatoora::InvoiceTotals*>(ptr);
}

inline fatoora::InvoiceTotals* fatoora::InvoiceTotals::FromFFI(fatoora::capi::InvoiceTotals* ptr) {
    return reinterpret_cast<fatoora::InvoiceTotals*>(ptr);
}

inline void fatoora::InvoiceTotals::operator delete(void* ptr) {
    fatoora::capi::fatoora_InvoiceTotals_destroy(reinterpret_cast<fatoora::capi::InvoiceTotals*>(ptr));
}


#endif // fatoora_InvoiceTotals_HPP
