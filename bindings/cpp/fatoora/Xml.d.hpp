#ifndef fatoora_Xml_D_HPP
#define fatoora_Xml_D_HPP

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
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct Xml;
} // namespace capi
} // namespace

namespace fatoora {
class Xml {
public:

  /**
   * Produce an owned local ZATCA report as JSON. Inspect is_valid before acceptance.
   * Options default when absent; JSON inputs are limited to 4 KiB.
   */
  inline static diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> validate_zatca(const fatoora::Config& config, std::string_view xml, std::optional<std::string_view> options_json);
  template<typename W>
  inline static diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> validate_zatca_write(const fatoora::Config& config, std::string_view xml, std::optional<std::string_view> options_json, W& writeable_output);

  inline static diplomat::result<bool, std::unique_ptr<fatoora::BindingError>> validate(const fatoora::Config& config, std::string_view xml);

  inline static diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> hash(std::string_view xml);
  template<typename W>
  inline static diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> hash_write(std::string_view xml, W& writeable_output);

    inline const fatoora::capi::Xml* AsFFI() const;
    inline fatoora::capi::Xml* AsFFI();
    inline static const fatoora::Xml* FromFFI(const fatoora::capi::Xml* ptr);
    inline static fatoora::Xml* FromFFI(fatoora::capi::Xml* ptr);
    inline static void operator delete(void* ptr);
private:
    Xml() = delete;
    Xml(const fatoora::Xml&) = delete;
    Xml(fatoora::Xml&&) noexcept = delete;
    Xml operator=(const fatoora::Xml&) = delete;
    Xml operator=(fatoora::Xml&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_Xml_D_HPP
