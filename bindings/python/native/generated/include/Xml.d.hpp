#ifndef _NATIVE_Xml_D_HPP
#define _NATIVE_Xml_D_HPP

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
} // namespace _native



namespace _native {
namespace capi {
    struct Xml;
} // namespace capi
} // namespace

namespace _native {
class Xml {
public:

  /**
   * Produce an owned local ZATCA report as JSON. Inspect is_valid before acceptance.
   * Options default when absent; JSON inputs are limited to 4 KiB.
   */
  inline static _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> validate_zatca(const _native::Config& config, std::string_view xml, std::optional<std::string_view> options_json);
  template<typename W>
  inline static _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> validate_zatca_write(const _native::Config& config, std::string_view xml, std::optional<std::string_view> options_json, W& writeable_output);

  inline static _native::diplomat::result<bool, std::unique_ptr<_native::BindingError>> validate(const _native::Config& config, std::string_view xml);

  inline static _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> hash(std::string_view xml);
  template<typename W>
  inline static _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> hash_write(std::string_view xml, W& writeable_output);

    inline const _native::capi::Xml* AsFFI() const;
    inline _native::capi::Xml* AsFFI();
    inline static const _native::Xml* FromFFI(const _native::capi::Xml* ptr);
    inline static _native::Xml* FromFFI(_native::capi::Xml* ptr);
    inline static void operator delete(void* ptr);
private:
    Xml() = delete;
    Xml(const _native::Xml&) = delete;
    Xml(_native::Xml&&) noexcept = delete;
    Xml operator=(const _native::Xml&) = delete;
    Xml operator=(_native::Xml&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_Xml_D_HPP
