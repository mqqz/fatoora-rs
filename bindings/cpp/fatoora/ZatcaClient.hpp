#ifndef fatoora_ZatcaClient_HPP
#define fatoora_ZatcaClient_HPP

#include "ZatcaClient.d.hpp"

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
#include "Config.hpp"
#include "CsidCompliance.hpp"
#include "CsidProduction.hpp"
#include "Csr.hpp"
#include "SignedInvoice.hpp"
#include "ValidationResponse.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_ZatcaClient_create_result {union {fatoora::capi::ZatcaClient* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_create_result;
    fatoora_ZatcaClient_create_result fatoora_ZatcaClient_create(const fatoora::capi::Config* config);

    typedef struct fatoora_ZatcaClient_post_csr_for_ccsid_result {union {fatoora::capi::CsidCompliance* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_post_csr_for_ccsid_result;
    fatoora_ZatcaClient_post_csr_for_ccsid_result fatoora_ZatcaClient_post_csr_for_ccsid(const fatoora::capi::ZatcaClient* self, const fatoora::capi::Csr* csr, diplomat::capi::DiplomatStringView otp);

    typedef struct fatoora_ZatcaClient_post_ccsid_for_pcsid_result {union {fatoora::capi::CsidProduction* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_post_ccsid_for_pcsid_result;
    fatoora_ZatcaClient_post_ccsid_for_pcsid_result fatoora_ZatcaClient_post_ccsid_for_pcsid(const fatoora::capi::ZatcaClient* self, const fatoora::capi::CsidCompliance* credentials);

    typedef struct fatoora_ZatcaClient_renew_csid_result {union {fatoora::capi::CsidProduction* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_renew_csid_result;
    fatoora_ZatcaClient_renew_csid_result fatoora_ZatcaClient_renew_csid(const fatoora::capi::ZatcaClient* self, const fatoora::capi::CsidProduction* credentials, const fatoora::capi::Csr* csr, diplomat::capi::DiplomatStringView otp, diplomat::capi::OptionStringView accept_language);

    typedef struct fatoora_ZatcaClient_check_invoice_compliance_result {union {fatoora::capi::ValidationResponse* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_check_invoice_compliance_result;
    fatoora_ZatcaClient_check_invoice_compliance_result fatoora_ZatcaClient_check_invoice_compliance(const fatoora::capi::ZatcaClient* self, const fatoora::capi::SignedInvoice* invoice, const fatoora::capi::CsidCompliance* credentials);

    typedef struct fatoora_ZatcaClient_report_simplified_invoice_result {union {fatoora::capi::ValidationResponse* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_report_simplified_invoice_result;
    fatoora_ZatcaClient_report_simplified_invoice_result fatoora_ZatcaClient_report_simplified_invoice(const fatoora::capi::ZatcaClient* self, const fatoora::capi::SignedInvoice* invoice, const fatoora::capi::CsidProduction* credentials, bool clearance_status, diplomat::capi::OptionStringView accept_language);

    typedef struct fatoora_ZatcaClient_clear_standard_invoice_result {union {fatoora::capi::ValidationResponse* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ZatcaClient_clear_standard_invoice_result;
    fatoora_ZatcaClient_clear_standard_invoice_result fatoora_ZatcaClient_clear_standard_invoice(const fatoora::capi::ZatcaClient* self, const fatoora::capi::SignedInvoice* invoice, const fatoora::capi::CsidProduction* credentials, bool clearance_status, diplomat::capi::OptionStringView accept_language);

    void fatoora_ZatcaClient_destroy(ZatcaClient* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<fatoora::ZatcaClient>, std::unique_ptr<fatoora::BindingError>> fatoora::ZatcaClient::create(const fatoora::Config& config) {
    auto result = fatoora::capi::fatoora_ZatcaClient_create(config.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::ZatcaClient>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::ZatcaClient>>(std::unique_ptr<fatoora::ZatcaClient>(fatoora::ZatcaClient::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::ZatcaClient>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::CsidCompliance>, std::unique_ptr<fatoora::BindingError>> fatoora::ZatcaClient::post_csr_for_ccsid(const fatoora::Csr& csr, std::string_view otp) const {
    auto result = fatoora::capi::fatoora_ZatcaClient_post_csr_for_ccsid(this->AsFFI(),
        csr.AsFFI(),
        {otp.data(), otp.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::CsidCompliance>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::CsidCompliance>>(std::unique_ptr<fatoora::CsidCompliance>(fatoora::CsidCompliance::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::CsidCompliance>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>> fatoora::ZatcaClient::post_ccsid_for_pcsid(const fatoora::CsidCompliance& credentials) const {
    auto result = fatoora::capi::fatoora_ZatcaClient_post_ccsid_for_pcsid(this->AsFFI(),
        credentials.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::CsidProduction>>(std::unique_ptr<fatoora::CsidProduction>(fatoora::CsidProduction::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>> fatoora::ZatcaClient::renew_csid(const fatoora::CsidProduction& credentials, const fatoora::Csr& csr, std::string_view otp, std::optional<std::string_view> accept_language) const {
    auto result = fatoora::capi::fatoora_ZatcaClient_renew_csid(this->AsFFI(),
        credentials.AsFFI(),
        csr.AsFFI(),
        {otp.data(), otp.size()},
        accept_language.has_value() ? (diplomat::capi::OptionStringView{ { {accept_language.value().data(), accept_language.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::CsidProduction>>(std::unique_ptr<fatoora::CsidProduction>(fatoora::CsidProduction::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>> fatoora::ZatcaClient::check_invoice_compliance(const fatoora::SignedInvoice& invoice, const fatoora::CsidCompliance& credentials) const {
    auto result = fatoora::capi::fatoora_ZatcaClient_check_invoice_compliance(this->AsFFI(),
        invoice.AsFFI(),
        credentials.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::ValidationResponse>>(std::unique_ptr<fatoora::ValidationResponse>(fatoora::ValidationResponse::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>> fatoora::ZatcaClient::report_simplified_invoice(const fatoora::SignedInvoice& invoice, const fatoora::CsidProduction& credentials, bool clearance_status, std::optional<std::string_view> accept_language) const {
    auto result = fatoora::capi::fatoora_ZatcaClient_report_simplified_invoice(this->AsFFI(),
        invoice.AsFFI(),
        credentials.AsFFI(),
        clearance_status,
        accept_language.has_value() ? (diplomat::capi::OptionStringView{ { {accept_language.value().data(), accept_language.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::ValidationResponse>>(std::unique_ptr<fatoora::ValidationResponse>(fatoora::ValidationResponse::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>> fatoora::ZatcaClient::clear_standard_invoice(const fatoora::SignedInvoice& invoice, const fatoora::CsidProduction& credentials, bool clearance_status, std::optional<std::string_view> accept_language) const {
    auto result = fatoora::capi::fatoora_ZatcaClient_clear_standard_invoice(this->AsFFI(),
        invoice.AsFFI(),
        credentials.AsFFI(),
        clearance_status,
        accept_language.has_value() ? (diplomat::capi::OptionStringView{ { {accept_language.value().data(), accept_language.value().size()} }, true }) : (diplomat::capi::OptionStringView{ {}, false }));
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::ValidationResponse>>(std::unique_ptr<fatoora::ValidationResponse>(fatoora::ValidationResponse::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::ZatcaClient* fatoora::ZatcaClient::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::ZatcaClient*>(this);
}

inline fatoora::capi::ZatcaClient* fatoora::ZatcaClient::AsFFI() {
    return reinterpret_cast<fatoora::capi::ZatcaClient*>(this);
}

inline const fatoora::ZatcaClient* fatoora::ZatcaClient::FromFFI(const fatoora::capi::ZatcaClient* ptr) {
    return reinterpret_cast<const fatoora::ZatcaClient*>(ptr);
}

inline fatoora::ZatcaClient* fatoora::ZatcaClient::FromFFI(fatoora::capi::ZatcaClient* ptr) {
    return reinterpret_cast<fatoora::ZatcaClient*>(ptr);
}

inline void fatoora::ZatcaClient::operator delete(void* ptr) {
    fatoora::capi::fatoora_ZatcaClient_destroy(reinterpret_cast<fatoora::capi::ZatcaClient*>(ptr));
}


#endif // fatoora_ZatcaClient_HPP
