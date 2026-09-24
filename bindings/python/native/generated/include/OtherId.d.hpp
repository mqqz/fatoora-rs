#ifndef _NATIVE_OtherId_D_HPP
#define _NATIVE_OtherId_D_HPP

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
    struct OtherId;
} // namespace capi
} // namespace

namespace _native {
class OtherId {
public:

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> value() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> value_write(W& writeable_output) const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> scheme() const;

    inline const _native::capi::OtherId* AsFFI() const;
    inline _native::capi::OtherId* AsFFI();
    inline static const _native::OtherId* FromFFI(const _native::capi::OtherId* ptr);
    inline static _native::OtherId* FromFFI(_native::capi::OtherId* ptr);
    inline static void operator delete(void* ptr);
private:
    OtherId() = delete;
    OtherId(const _native::OtherId&) = delete;
    OtherId(_native::OtherId&&) noexcept = delete;
    OtherId operator=(const _native::OtherId&) = delete;
    OtherId operator=(_native::OtherId&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_OtherId_D_HPP
