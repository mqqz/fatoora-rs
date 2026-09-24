#ifndef _NATIVE_CsidProduction_D_HPP
#define _NATIVE_CsidProduction_D_HPP

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
namespace capi { struct CsidProduction; }
class CsidProduction;
namespace capi { struct Text; }
class Text;
} // namespace _native



namespace _native {
namespace capi {
    struct CsidProduction;
} // namespace capi
} // namespace

namespace _native {
class CsidProduction {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::CsidProduction>, std::unique_ptr<_native::BindingError>> create(uint8_t environment, std::optional<std::string_view> request_id, std::string_view token, std::string_view secret);

  inline uint8_t env() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> request_id() const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> binary_security_token() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> binary_security_token_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> secret() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> secret_write(W& writeable_output) const;

    inline const _native::capi::CsidProduction* AsFFI() const;
    inline _native::capi::CsidProduction* AsFFI();
    inline static const _native::CsidProduction* FromFFI(const _native::capi::CsidProduction* ptr);
    inline static _native::CsidProduction* FromFFI(_native::capi::CsidProduction* ptr);
    inline static void operator delete(void* ptr);
private:
    CsidProduction() = delete;
    CsidProduction(const _native::CsidProduction&) = delete;
    CsidProduction(_native::CsidProduction&&) noexcept = delete;
    CsidProduction operator=(const _native::CsidProduction&) = delete;
    CsidProduction operator=(_native::CsidProduction&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_CsidProduction_D_HPP
