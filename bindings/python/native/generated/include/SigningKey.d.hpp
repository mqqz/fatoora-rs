#ifndef _NATIVE_SigningKey_D_HPP
#define _NATIVE_SigningKey_D_HPP

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
namespace capi { struct SigningKey; }
class SigningKey;
} // namespace _native



namespace _native {
namespace capi {
    struct SigningKey;
} // namespace capi
} // namespace

namespace _native {
class SigningKey {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>> generate();

  inline static _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>> from_pem(std::string_view pem);

  inline static _native::diplomat::result<std::unique_ptr<_native::SigningKey>, std::unique_ptr<_native::BindingError>> from_der(_native::diplomat::span<const uint8_t> der);

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> to_pem() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> to_pem_write(W& writeable_output) const;

  inline _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>> to_der() const;

    inline const _native::capi::SigningKey* AsFFI() const;
    inline _native::capi::SigningKey* AsFFI();
    inline static const _native::SigningKey* FromFFI(const _native::capi::SigningKey* ptr);
    inline static _native::SigningKey* FromFFI(_native::capi::SigningKey* ptr);
    inline static void operator delete(void* ptr);
private:
    SigningKey() = delete;
    SigningKey(const _native::SigningKey&) = delete;
    SigningKey(_native::SigningKey&&) noexcept = delete;
    SigningKey operator=(const _native::SigningKey&) = delete;
    SigningKey operator=(_native::SigningKey&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_SigningKey_D_HPP
