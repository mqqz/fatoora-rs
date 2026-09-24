#ifndef _NATIVE_ValidationResults_D_HPP
#define _NATIVE_ValidationResults_D_HPP

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
namespace capi { struct ValidationMessage; }
class ValidationMessage;
} // namespace _native



namespace _native {
namespace capi {
    struct ValidationResults;
} // namespace capi
} // namespace

namespace _native {
class ValidationResults {
public:

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> status() const;

  inline size_t info_len() const;

  inline _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>> info_message(size_t index) const;

  inline size_t warning_len() const;

  inline _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>> warning_message(size_t index) const;

  inline size_t error_len() const;

  inline _native::diplomat::result<std::unique_ptr<_native::ValidationMessage>, std::unique_ptr<_native::BindingError>> error_message(size_t index) const;

    inline const _native::capi::ValidationResults* AsFFI() const;
    inline _native::capi::ValidationResults* AsFFI();
    inline static const _native::ValidationResults* FromFFI(const _native::capi::ValidationResults* ptr);
    inline static _native::ValidationResults* FromFFI(_native::capi::ValidationResults* ptr);
    inline static void operator delete(void* ptr);
private:
    ValidationResults() = delete;
    ValidationResults(const _native::ValidationResults&) = delete;
    ValidationResults(_native::ValidationResults&&) noexcept = delete;
    ValidationResults operator=(const _native::ValidationResults&) = delete;
    ValidationResults operator=(_native::ValidationResults&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_ValidationResults_D_HPP
