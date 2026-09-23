#ifndef fatoora_CsidProduction_D_HPP
#define fatoora_CsidProduction_D_HPP

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
namespace capi { struct CsidProduction; }
class CsidProduction;
namespace capi { struct Text; }
class Text;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct CsidProduction;
} // namespace capi
} // namespace

namespace fatoora {
class CsidProduction {
public:

  inline static diplomat::result<std::unique_ptr<fatoora::CsidProduction>, std::unique_ptr<fatoora::BindingError>> create(uint8_t environment, std::optional<std::string_view> request_id, std::string_view token, std::string_view secret);

  inline uint8_t env() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> request_id() const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> binary_security_token() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> binary_security_token_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> secret() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> secret_write(W& writeable_output) const;

    inline const fatoora::capi::CsidProduction* AsFFI() const;
    inline fatoora::capi::CsidProduction* AsFFI();
    inline static const fatoora::CsidProduction* FromFFI(const fatoora::capi::CsidProduction* ptr);
    inline static fatoora::CsidProduction* FromFFI(fatoora::capi::CsidProduction* ptr);
    inline static void operator delete(void* ptr);
private:
    CsidProduction() = delete;
    CsidProduction(const fatoora::CsidProduction&) = delete;
    CsidProduction(fatoora::CsidProduction&&) noexcept = delete;
    CsidProduction operator=(const fatoora::CsidProduction&) = delete;
    CsidProduction operator=(fatoora::CsidProduction&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_CsidProduction_D_HPP
