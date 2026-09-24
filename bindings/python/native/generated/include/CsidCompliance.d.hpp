#ifndef _NATIVE_CsidCompliance_D_HPP
#define _NATIVE_CsidCompliance_D_HPP

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
namespace capi { struct CsidCompliance; }
class CsidCompliance;
namespace capi { struct Text; }
class Text;
} // namespace _native



namespace _native {
namespace capi {
    struct CsidCompliance;
} // namespace capi
} // namespace

namespace _native {
class CsidCompliance {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::CsidCompliance>, std::unique_ptr<_native::BindingError>> create(uint8_t environment, std::optional<std::string_view> request_id, std::string_view token, std::string_view secret);

  inline uint8_t env() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> request_id() const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> binary_security_token() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> binary_security_token_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> secret() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> secret_write(W& writeable_output) const;

    inline const _native::capi::CsidCompliance* AsFFI() const;
    inline _native::capi::CsidCompliance* AsFFI();
    inline static const _native::CsidCompliance* FromFFI(const _native::capi::CsidCompliance* ptr);
    inline static _native::CsidCompliance* FromFFI(_native::capi::CsidCompliance* ptr);
    inline static void operator delete(void* ptr);
private:
    CsidCompliance() = delete;
    CsidCompliance(const _native::CsidCompliance&) = delete;
    CsidCompliance(_native::CsidCompliance&&) noexcept = delete;
    CsidCompliance operator=(const _native::CsidCompliance&) = delete;
    CsidCompliance operator=(_native::CsidCompliance&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_CsidCompliance_D_HPP
