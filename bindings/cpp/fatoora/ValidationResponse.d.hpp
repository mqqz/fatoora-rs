#ifndef fatoora_ValidationResponse_D_HPP
#define fatoora_ValidationResponse_D_HPP

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
namespace capi { struct Text; }
class Text;
namespace capi { struct ValidationResults; }
class ValidationResults;
class InvoiceOutcome;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct ValidationResponse;
} // namespace capi
} // namespace

namespace fatoora {
class ValidationResponse {
public:

  inline std::optional<uint16_t> http_status() const;

  inline fatoora::InvoiceOutcome outcome() const;

  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> ensure_accepted() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> cleared_invoice_xml() const;

  inline diplomat::result<std::unique_ptr<fatoora::ValidationResults>, std::unique_ptr<fatoora::BindingError>> validation_results() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> cleared_invoice_base64() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> reporting_status() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> clearance_status() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> qr_seller_status() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> qr_buyer_status() const;

    inline const fatoora::capi::ValidationResponse* AsFFI() const;
    inline fatoora::capi::ValidationResponse* AsFFI();
    inline static const fatoora::ValidationResponse* FromFFI(const fatoora::capi::ValidationResponse* ptr);
    inline static fatoora::ValidationResponse* FromFFI(fatoora::capi::ValidationResponse* ptr);
    inline static void operator delete(void* ptr);
private:
    ValidationResponse() = delete;
    ValidationResponse(const fatoora::ValidationResponse&) = delete;
    ValidationResponse(fatoora::ValidationResponse&&) noexcept = delete;
    ValidationResponse operator=(const fatoora::ValidationResponse&) = delete;
    ValidationResponse operator=(fatoora::ValidationResponse&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_ValidationResponse_D_HPP
