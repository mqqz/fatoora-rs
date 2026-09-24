#ifndef _NATIVE_Party_D_HPP
#define _NATIVE_Party_D_HPP

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
namespace capi { struct Address; }
class Address;
namespace capi { struct BindingError; }
class BindingError;
namespace capi { struct OtherId; }
class OtherId;
namespace capi { struct VatId; }
class VatId;
} // namespace _native



namespace _native {
namespace capi {
    struct Party;
} // namespace capi
} // namespace

namespace _native {
class Party {
public:

  inline _native::diplomat::result<std::unique_ptr<_native::Address>, std::unique_ptr<_native::BindingError>> address() const;

  inline _native::diplomat::result<std::unique_ptr<_native::VatId>, std::unique_ptr<_native::BindingError>> vat_id() const;

  inline _native::diplomat::result<std::unique_ptr<_native::OtherId>, std::unique_ptr<_native::BindingError>> other_id() const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> name() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> name_write(W& writeable_output) const;

    inline const _native::capi::Party* AsFFI() const;
    inline _native::capi::Party* AsFFI();
    inline static const _native::Party* FromFFI(const _native::capi::Party* ptr);
    inline static _native::Party* FromFFI(_native::capi::Party* ptr);
    inline static void operator delete(void* ptr);
private:
    Party() = delete;
    Party(const _native::Party&) = delete;
    Party(_native::Party&&) noexcept = delete;
    Party operator=(const _native::Party&) = delete;
    Party operator=(_native::Party&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_Party_D_HPP
