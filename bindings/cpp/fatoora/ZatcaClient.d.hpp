#ifndef fatoora_ZatcaClient_D_HPP
#define fatoora_ZatcaClient_D_HPP

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "../diplomat_runtime.hpp"

namespace fatoora {
namespace capi { struct BindingError; }
class BindingError;
namespace capi { struct Config; }
class Config;
namespace capi { struct CsidCompliance; }
class CsidCompliance;
namespace capi { struct CsidProduction; }
class CsidProduction;
namespace capi { struct Csr; }
class Csr;
namespace capi { struct SignedInvoice; }
class SignedInvoice;
namespace capi { struct ValidationResponse; }
class ValidationResponse;
namespace capi { struct ZatcaClient; }
class ZatcaClient;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct ZatcaClient;
} // namespace capi
} // namespace

namespace fatoora {
class ZatcaClient {
public:

  inline static diplomat::result<std::unique_ptr<fatoora::ZatcaClient>, std::unique_ptr<fatoora::BindingError>> create(const fatoora::Config& config);

  inline diplomat::result<std::unique_ptr<fatoora::CsidCompliance>, std::unique_ptr<fatoora::BindingError>> post_csr_for_ccsid(const fatoora::Csr& csr, std::string_view otp) const;

  inline diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>> post_ccsid_for_pcsid(const fatoora::CsidCompliance& credentials) const;

  inline diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>> renew_csid(const fatoora::CsidProduction& credentials, const fatoora::Csr& csr, std::string_view otp, std::optional<std::string_view> accept_language) const;

  inline diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>> check_invoice_compliance(const fatoora::SignedInvoice& invoice, const fatoora::CsidCompliance& credentials) const;

  inline diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>> report_simplified_invoice(const fatoora::SignedInvoice& invoice, const fatoora::CsidProduction& credentials, bool clearance_status, std::optional<std::string_view> accept_language) const;

  inline diplomat::result<std::unique_ptr<fatoora::ValidationResponse>, std::unique_ptr<fatoora::BindingError>> clear_standard_invoice(const fatoora::SignedInvoice& invoice, const fatoora::CsidProduction& credentials, bool clearance_status, std::optional<std::string_view> accept_language) const;

    inline const fatoora::capi::ZatcaClient* AsFFI() const;
    inline fatoora::capi::ZatcaClient* AsFFI();
    inline static const fatoora::ZatcaClient* FromFFI(const fatoora::capi::ZatcaClient* ptr);
    inline static fatoora::ZatcaClient* FromFFI(fatoora::capi::ZatcaClient* ptr);
    inline static void operator delete(void* ptr);
private:
    ZatcaClient() = delete;
    ZatcaClient(const fatoora::ZatcaClient&) = delete;
    ZatcaClient(fatoora::ZatcaClient&&) noexcept = delete;
    ZatcaClient operator=(const fatoora::ZatcaClient&) = delete;
    ZatcaClient operator=(fatoora::ZatcaClient&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_ZatcaClient_D_HPP
