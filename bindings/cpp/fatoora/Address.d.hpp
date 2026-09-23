#ifndef fatoora_Address_D_HPP
#define fatoora_Address_D_HPP

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
namespace capi { struct Address; }
class Address;
namespace capi { struct BindingError; }
class BindingError;
namespace capi { struct Text; }
class Text;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct Address;
} // namespace capi
} // namespace

namespace fatoora {
class Address {
public:

  inline static diplomat::result<std::unique_ptr<fatoora::Address>, std::unique_ptr<fatoora::BindingError>> new_(std::string_view country_code, std::string_view city, std::string_view street, std::string_view building_number, std::string_view postal_code, std::optional<std::string_view> additional_street, std::optional<std::string_view> additional_number, std::optional<std::string_view> district);

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> city() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> city_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> street() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> street_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> building_number() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> building_number_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> postal_code() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> postal_code_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> country_code() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> country_code_write(W& writeable_output) const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> additional_street() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> additional_number() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> district() const;

    inline const fatoora::capi::Address* AsFFI() const;
    inline fatoora::capi::Address* AsFFI();
    inline static const fatoora::Address* FromFFI(const fatoora::capi::Address* ptr);
    inline static fatoora::Address* FromFFI(fatoora::capi::Address* ptr);
    inline static void operator delete(void* ptr);
private:
    Address() = delete;
    Address(const fatoora::Address&) = delete;
    Address(fatoora::Address&&) noexcept = delete;
    Address operator=(const fatoora::Address&) = delete;
    Address operator=(fatoora::Address&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_Address_D_HPP
