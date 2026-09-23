#ifndef _NATIVE_CsrProperties_D_HPP
#define _NATIVE_CsrProperties_D_HPP

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
namespace capi { struct Csr; }
class Csr;
namespace capi { struct CsrProperties; }
class CsrProperties;
namespace capi { struct SigningKey; }
class SigningKey;
} // namespace _native



namespace _native {
namespace capi {
    struct CsrProperties;
} // namespace capi
} // namespace

namespace _native {
class CsrProperties {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>> new_(std::string_view common_name, std::string_view serial_number, std::string_view organization_identifier, std::string_view organization_unit_name, std::string_view organization_name, std::string_view country_name, std::string_view invoice_type, std::string_view location_address, std::string_view industry_business_category);

  inline static _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>> from_properties_str(std::string_view properties);

  inline static _native::diplomat::result<std::unique_ptr<_native::CsrProperties>, std::unique_ptr<_native::BindingError>> parse_csr_config_file(std::string_view path);

  inline _native::diplomat::result<std::unique_ptr<_native::Csr>, std::unique_ptr<_native::BindingError>> build(const _native::SigningKey& key, uint8_t env) const;

    inline const _native::capi::CsrProperties* AsFFI() const;
    inline _native::capi::CsrProperties* AsFFI();
    inline static const _native::CsrProperties* FromFFI(const _native::capi::CsrProperties* ptr);
    inline static _native::CsrProperties* FromFFI(_native::capi::CsrProperties* ptr);
    inline static void operator delete(void* ptr);
private:
    CsrProperties() = delete;
    CsrProperties(const _native::CsrProperties&) = delete;
    CsrProperties(_native::CsrProperties&&) noexcept = delete;
    CsrProperties operator=(const _native::CsrProperties&) = delete;
    CsrProperties operator=(_native::CsrProperties&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_CsrProperties_D_HPP
