#ifndef _NATIVE_BytesList_D_HPP
#define _NATIVE_BytesList_D_HPP

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
namespace capi { struct Bytes; }
class Bytes;
} // namespace _native



namespace _native {
namespace capi {
    struct BytesList;
} // namespace capi
} // namespace

namespace _native {
class BytesList {
public:

  inline size_t len() const;

  inline bool is_empty() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>> get(size_t index) const;

    inline const _native::capi::BytesList* AsFFI() const;
    inline _native::capi::BytesList* AsFFI();
    inline static const _native::BytesList* FromFFI(const _native::capi::BytesList* ptr);
    inline static _native::BytesList* FromFFI(_native::capi::BytesList* ptr);
    inline static void operator delete(void* ptr);
private:
    BytesList() = delete;
    BytesList(const _native::BytesList&) = delete;
    BytesList(_native::BytesList&&) noexcept = delete;
    BytesList operator=(const _native::BytesList&) = delete;
    BytesList operator=(_native::BytesList&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_BytesList_D_HPP
