#ifndef _NATIVE_ValidationResponse_D_HPP
#define _NATIVE_ValidationResponse_D_HPP

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
namespace capi { struct Text; }
class Text;
namespace capi { struct ValidationResults; }
class ValidationResults;
class InvoiceOutcome;
} // namespace _native



namespace _native {
namespace capi {
    struct ValidationResponse;
} // namespace capi
} // namespace

namespace _native {
class ValidationResponse {
public:

  inline std::optional<uint16_t> http_status() const;

  inline _native::InvoiceOutcome outcome() const;

  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> ensure_accepted() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> cleared_invoice_xml() const;

  inline _native::diplomat::result<std::unique_ptr<_native::ValidationResults>, std::unique_ptr<_native::BindingError>> validation_results() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> cleared_invoice_base64() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> reporting_status() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> clearance_status() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> qr_seller_status() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> qr_buyer_status() const;

    inline const _native::capi::ValidationResponse* AsFFI() const;
    inline _native::capi::ValidationResponse* AsFFI();
    inline static const _native::ValidationResponse* FromFFI(const _native::capi::ValidationResponse* ptr);
    inline static _native::ValidationResponse* FromFFI(_native::capi::ValidationResponse* ptr);
    inline static void operator delete(void* ptr);
private:
    ValidationResponse() = delete;
    ValidationResponse(const _native::ValidationResponse&) = delete;
    ValidationResponse(_native::ValidationResponse&&) noexcept = delete;
    ValidationResponse operator=(const _native::ValidationResponse&) = delete;
    ValidationResponse operator=(_native::ValidationResponse&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_ValidationResponse_D_HPP
