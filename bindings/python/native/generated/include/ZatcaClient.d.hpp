#ifndef _NATIVE_ZatcaClient_D_HPP
#define _NATIVE_ZatcaClient_D_HPP

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "diplomat_runtime.hpp"
namespace _native {
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
} // namespace _native



namespace _native {
namespace capi {
    struct ZatcaClient;
} // namespace capi
} // namespace

namespace _native {
class ZatcaClient {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::ZatcaClient>, std::unique_ptr<_native::BindingError>> create(const _native::Config& config);

  inline _native::diplomat::result<std::unique_ptr<_native::CsidCompliance>, std::unique_ptr<_native::BindingError>> post_csr_for_ccsid(const _native::Csr& csr, std::string_view otp) const;

  inline _native::diplomat::result<std::unique_ptr<_native::CsidProduction>, std::unique_ptr<_native::BindingError>> post_ccsid_for_pcsid(const _native::CsidCompliance& credentials) const;

  inline _native::diplomat::result<std::unique_ptr<_native::CsidProduction>, std::unique_ptr<_native::BindingError>> renew_csid(const _native::CsidProduction& credentials, const _native::Csr& csr, std::string_view otp, std::optional<std::string_view> accept_language) const;

  inline _native::diplomat::result<std::unique_ptr<_native::ValidationResponse>, std::unique_ptr<_native::BindingError>> check_invoice_compliance(const _native::SignedInvoice& invoice, const _native::CsidCompliance& credentials) const;

  inline _native::diplomat::result<std::unique_ptr<_native::ValidationResponse>, std::unique_ptr<_native::BindingError>> report_simplified_invoice(const _native::SignedInvoice& invoice, const _native::CsidProduction& credentials, bool clearance_status, std::optional<std::string_view> accept_language) const;

  inline _native::diplomat::result<std::unique_ptr<_native::ValidationResponse>, std::unique_ptr<_native::BindingError>> clear_standard_invoice(const _native::SignedInvoice& invoice, const _native::CsidProduction& credentials, bool clearance_status, std::optional<std::string_view> accept_language) const;

    inline const _native::capi::ZatcaClient* AsFFI() const;
    inline _native::capi::ZatcaClient* AsFFI();
    inline static const _native::ZatcaClient* FromFFI(const _native::capi::ZatcaClient* ptr);
    inline static _native::ZatcaClient* FromFFI(_native::capi::ZatcaClient* ptr);
    inline static void operator delete(void* ptr);
private:
    ZatcaClient() = delete;
    ZatcaClient(const _native::ZatcaClient&) = delete;
    ZatcaClient(_native::ZatcaClient&&) noexcept = delete;
    ZatcaClient operator=(const _native::ZatcaClient&) = delete;
    ZatcaClient operator=(_native::ZatcaClient&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_ZatcaClient_D_HPP
