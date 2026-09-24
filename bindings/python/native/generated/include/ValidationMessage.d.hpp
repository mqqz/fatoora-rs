#ifndef _NATIVE_ValidationMessage_D_HPP
#define _NATIVE_ValidationMessage_D_HPP

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
} // namespace _native



namespace _native {
namespace capi {
    struct ValidationMessage;
} // namespace capi
} // namespace

namespace _native {
class ValidationMessage {
public:

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> message_type() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> code() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> category() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> message() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> status() const;

    inline const _native::capi::ValidationMessage* AsFFI() const;
    inline _native::capi::ValidationMessage* AsFFI();
    inline static const _native::ValidationMessage* FromFFI(const _native::capi::ValidationMessage* ptr);
    inline static _native::ValidationMessage* FromFFI(_native::capi::ValidationMessage* ptr);
    inline static void operator delete(void* ptr);
private:
    ValidationMessage() = delete;
    ValidationMessage(const _native::ValidationMessage&) = delete;
    ValidationMessage(_native::ValidationMessage&&) noexcept = delete;
    ValidationMessage operator=(const _native::ValidationMessage&) = delete;
    ValidationMessage operator=(_native::ValidationMessage&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_ValidationMessage_D_HPP
