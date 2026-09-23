#ifndef _NATIVE_VatId_D_HPP
#define _NATIVE_VatId_D_HPP

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
    struct VatId;
} // namespace capi
} // namespace

namespace _native {
class VatId {
public:

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> value() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> value_write(W& writeable_output) const;

    inline const _native::capi::VatId* AsFFI() const;
    inline _native::capi::VatId* AsFFI();
    inline static const _native::VatId* FromFFI(const _native::capi::VatId* ptr);
    inline static _native::VatId* FromFFI(_native::capi::VatId* ptr);
    inline static void operator delete(void* ptr);
private:
    VatId() = delete;
    VatId(const _native::VatId&) = delete;
    VatId(_native::VatId&&) noexcept = delete;
    VatId operator=(const _native::VatId&) = delete;
    VatId operator=(_native::VatId&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_VatId_D_HPP
