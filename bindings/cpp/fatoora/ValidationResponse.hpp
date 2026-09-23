#ifndef fatoora_ValidationResponse_HPP
#define fatoora_ValidationResponse_HPP

#include "ValidationResponse.d.hpp"

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
#include "InvoiceOutcome.hpp"
#include "Text.hpp"
#include "ValidationResults.hpp"


namespace fatoora {
namespace capi {
    extern "C" {

    typedef struct fatoora_ValidationResponse_http_status_result {union {uint16_t ok; }; bool is_ok;} fatoora_ValidationResponse_http_status_result;
    fatoora_ValidationResponse_http_status_result fatoora_ValidationResponse_http_status(const fatoora::capi::ValidationResponse* self);

    fatoora::capi::InvoiceOutcome fatoora_ValidationResponse_outcome(const fatoora::capi::ValidationResponse* self);

    typedef struct fatoora_ValidationResponse_ensure_accepted_result {union { fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_ensure_accepted_result;
    fatoora_ValidationResponse_ensure_accepted_result fatoora_ValidationResponse_ensure_accepted(const fatoora::capi::ValidationResponse* self);

    typedef struct fatoora_ValidationResponse_cleared_invoice_xml_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_cleared_invoice_xml_result;
    fatoora_ValidationResponse_cleared_invoice_xml_result fatoora_ValidationResponse_cleared_invoice_xml(const fatoora::capi::ValidationResponse* self);

    typedef struct fatoora_ValidationResponse_validation_results_result {union {fatoora::capi::ValidationResults* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_validation_results_result;
    fatoora_ValidationResponse_validation_results_result fatoora_ValidationResponse_validation_results(const fatoora::capi::ValidationResponse* self);

    typedef struct fatoora_ValidationResponse_cleared_invoice_base64_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_cleared_invoice_base64_result;
    fatoora_ValidationResponse_cleared_invoice_base64_result fatoora_ValidationResponse_cleared_invoice_base64(const fatoora::capi::ValidationResponse* self);

    typedef struct fatoora_ValidationResponse_reporting_status_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_reporting_status_result;
    fatoora_ValidationResponse_reporting_status_result fatoora_ValidationResponse_reporting_status(const fatoora::capi::ValidationResponse* self);

    typedef struct fatoora_ValidationResponse_clearance_status_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_clearance_status_result;
    fatoora_ValidationResponse_clearance_status_result fatoora_ValidationResponse_clearance_status(const fatoora::capi::ValidationResponse* self);

    typedef struct fatoora_ValidationResponse_qr_seller_status_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_qr_seller_status_result;
    fatoora_ValidationResponse_qr_seller_status_result fatoora_ValidationResponse_qr_seller_status(const fatoora::capi::ValidationResponse* self);

    typedef struct fatoora_ValidationResponse_qr_buyer_status_result {union {fatoora::capi::Text* ok; fatoora::capi::BindingError* err;}; bool is_ok;} fatoora_ValidationResponse_qr_buyer_status_result;
    fatoora_ValidationResponse_qr_buyer_status_result fatoora_ValidationResponse_qr_buyer_status(const fatoora::capi::ValidationResponse* self);

    void fatoora_ValidationResponse_destroy(ValidationResponse* self);

    } // extern "C"
} // namespace capi
} // namespace

inline std::optional<uint16_t> fatoora::ValidationResponse::http_status() const {
    auto result = fatoora::capi::fatoora_ValidationResponse_http_status(this->AsFFI());
    return result.is_ok ? std::optional<uint16_t>(result.ok) : std::nullopt;
}

inline fatoora::InvoiceOutcome fatoora::ValidationResponse::outcome() const {
    auto result = fatoora::capi::fatoora_ValidationResponse_outcome(this->AsFFI());
    return fatoora::InvoiceOutcome::FromFFI(result);
}

inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResponse::ensure_accepted() const {
    auto result = fatoora::capi::fatoora_ValidationResponse_ensure_accepted(this->AsFFI());
    return result.is_ok ? diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResponse::cleared_invoice_xml() const {
    auto result = fatoora::capi::fatoora_ValidationResponse_cleared_invoice_xml(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::ValidationResults>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResponse::validation_results() const {
    auto result = fatoora::capi::fatoora_ValidationResponse_validation_results(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::ValidationResults>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::ValidationResults>>(std::unique_ptr<fatoora::ValidationResults>(fatoora::ValidationResults::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::ValidationResults>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResponse::cleared_invoice_base64() const {
    auto result = fatoora::capi::fatoora_ValidationResponse_cleared_invoice_base64(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResponse::reporting_status() const {
    auto result = fatoora::capi::fatoora_ValidationResponse_reporting_status(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResponse::clearance_status() const {
    auto result = fatoora::capi::fatoora_ValidationResponse_clearance_status(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResponse::qr_seller_status() const {
    auto result = fatoora::capi::fatoora_ValidationResponse_qr_seller_status(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> fatoora::ValidationResponse::qr_buyer_status() const {
    auto result = fatoora::capi::fatoora_ValidationResponse_qr_buyer_status(this->AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Ok<std::unique_ptr<fatoora::Text>>(std::unique_ptr<fatoora::Text>(fatoora::Text::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>>(diplomat::Err<std::unique_ptr<fatoora::BindingError>>(std::unique_ptr<fatoora::BindingError>(fatoora::BindingError::FromFFI(result.err))));
}

inline const fatoora::capi::ValidationResponse* fatoora::ValidationResponse::AsFFI() const {
    return reinterpret_cast<const fatoora::capi::ValidationResponse*>(this);
}

inline fatoora::capi::ValidationResponse* fatoora::ValidationResponse::AsFFI() {
    return reinterpret_cast<fatoora::capi::ValidationResponse*>(this);
}

inline const fatoora::ValidationResponse* fatoora::ValidationResponse::FromFFI(const fatoora::capi::ValidationResponse* ptr) {
    return reinterpret_cast<const fatoora::ValidationResponse*>(ptr);
}

inline fatoora::ValidationResponse* fatoora::ValidationResponse::FromFFI(fatoora::capi::ValidationResponse* ptr) {
    return reinterpret_cast<fatoora::ValidationResponse*>(ptr);
}

inline void fatoora::ValidationResponse::operator delete(void* ptr) {
    fatoora::capi::fatoora_ValidationResponse_destroy(reinterpret_cast<fatoora::capi::ValidationResponse*>(ptr));
}


#endif // fatoora_ValidationResponse_HPP
