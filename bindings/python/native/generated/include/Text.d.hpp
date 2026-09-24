#ifndef _NATIVE_Text_D_HPP
#define _NATIVE_Text_D_HPP

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
} // namespace _native



namespace _native {
namespace capi {
    struct Text;
} // namespace capi
} // namespace

namespace _native {
class Text {
public:

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> value() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> value_write(W& writeable_output) const;

    inline const _native::capi::Text* AsFFI() const;
    inline _native::capi::Text* AsFFI();
    inline static const _native::Text* FromFFI(const _native::capi::Text* ptr);
    inline static _native::Text* FromFFI(_native::capi::Text* ptr);
    inline static void operator delete(void* ptr);
private:
    Text() = delete;
    Text(const _native::Text&) = delete;
    Text(_native::Text&&) noexcept = delete;
    Text operator=(const _native::Text&) = delete;
    Text operator=(_native::Text&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_Text_D_HPP
