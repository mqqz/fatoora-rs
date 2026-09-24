#ifndef fatoora_ValidationResults_D_HPP
#define fatoora_ValidationResults_D_HPP

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
namespace capi { struct ValidationMessage; }
class ValidationMessage;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct ValidationResults;
} // namespace capi
} // namespace

namespace fatoora {
class ValidationResults {
public:

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> status() const;

  inline size_t info_len() const;

  inline diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>> info_message(size_t index) const;

  inline size_t warning_len() const;

  inline diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>> warning_message(size_t index) const;

  inline size_t error_len() const;

  inline diplomat::result<std::unique_ptr<fatoora::ValidationMessage>, std::unique_ptr<fatoora::BindingError>> error_message(size_t index) const;

    inline const fatoora::capi::ValidationResults* AsFFI() const;
    inline fatoora::capi::ValidationResults* AsFFI();
    inline static const fatoora::ValidationResults* FromFFI(const fatoora::capi::ValidationResults* ptr);
    inline static fatoora::ValidationResults* FromFFI(fatoora::capi::ValidationResults* ptr);
    inline static void operator delete(void* ptr);
private:
    ValidationResults() = delete;
    ValidationResults(const fatoora::ValidationResults&) = delete;
    ValidationResults(fatoora::ValidationResults&&) noexcept = delete;
    ValidationResults operator=(const fatoora::ValidationResults&) = delete;
    ValidationResults operator=(fatoora::ValidationResults&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_ValidationResults_D_HPP
