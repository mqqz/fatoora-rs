#ifndef _NATIVE_Address_D_HPP
#define _NATIVE_Address_D_HPP

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
namespace capi { struct Address; }
class Address;
namespace capi { struct BindingError; }
class BindingError;
namespace capi { struct Text; }
class Text;
} // namespace _native



namespace _native {
namespace capi {
    struct Address;
} // namespace capi
} // namespace

namespace _native {
class Address {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::Address>, std::unique_ptr<_native::BindingError>> new_(std::string_view country_code, std::string_view city, std::string_view street, std::string_view building_number, std::string_view postal_code, std::optional<std::string_view> additional_street, std::optional<std::string_view> additional_number, std::optional<std::string_view> district);

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> city() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> city_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> street() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> street_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> building_number() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> building_number_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> postal_code() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> postal_code_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> country_code() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> country_code_write(W& writeable_output) const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> additional_street() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> additional_number() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> district() const;

    inline const _native::capi::Address* AsFFI() const;
    inline _native::capi::Address* AsFFI();
    inline static const _native::Address* FromFFI(const _native::capi::Address* ptr);
    inline static _native::Address* FromFFI(_native::capi::Address* ptr);
    inline static void operator delete(void* ptr);
private:
    Address() = delete;
    Address(const _native::Address&) = delete;
    Address(_native::Address&&) noexcept = delete;
    Address operator=(const _native::Address&) = delete;
    Address operator=(_native::Address&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_Address_D_HPP
