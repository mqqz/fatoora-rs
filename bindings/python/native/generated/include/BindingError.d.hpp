#ifndef _NATIVE_BindingError_D_HPP
#define _NATIVE_BindingError_D_HPP

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
namespace capi {
    struct BindingError;
} // namespace capi
} // namespace

namespace _native {
class BindingError {
public:

  inline int32_t code() const;

  inline std::string message() const;
  template<typename W>
  inline void message_write(W& writeable_output) const;

  inline std::string details_json() const;
  template<typename W>
  inline void details_json_write(W& writeable_output) const;

    inline const _native::capi::BindingError* AsFFI() const;
    inline _native::capi::BindingError* AsFFI();
    inline static const _native::BindingError* FromFFI(const _native::capi::BindingError* ptr);
    inline static _native::BindingError* FromFFI(_native::capi::BindingError* ptr);
    inline static void operator delete(void* ptr);
private:
    BindingError() = delete;
    BindingError(const _native::BindingError&) = delete;
    BindingError(_native::BindingError&&) noexcept = delete;
    BindingError operator=(const _native::BindingError&) = delete;
    BindingError operator=(_native::BindingError&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_BindingError_D_HPP
