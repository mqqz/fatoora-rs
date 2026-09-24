#ifndef _NATIVE_Bytes_D_HPP
#define _NATIVE_Bytes_D_HPP

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
    struct Bytes;
} // namespace capi
} // namespace

namespace _native {
class Bytes {
public:

  /**
   * The view is valid while this immutable owner remains alive.
   */
  inline _native::diplomat::span<const uint8_t> as_slice() const DIPLOMAT_LIFETIME_BOUND;

    inline const _native::capi::Bytes* AsFFI() const;
    inline _native::capi::Bytes* AsFFI();
    inline static const _native::Bytes* FromFFI(const _native::capi::Bytes* ptr);
    inline static _native::Bytes* FromFFI(_native::capi::Bytes* ptr);
    inline static void operator delete(void* ptr);
private:
    Bytes() = delete;
    Bytes(const _native::Bytes&) = delete;
    Bytes(_native::Bytes&&) noexcept = delete;
    Bytes operator=(const _native::Bytes&) = delete;
    Bytes operator=(_native::Bytes&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_Bytes_D_HPP
