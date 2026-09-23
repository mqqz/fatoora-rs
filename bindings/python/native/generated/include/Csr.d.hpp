#ifndef _NATIVE_Csr_D_HPP
#define _NATIVE_Csr_D_HPP

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
namespace capi { struct BytesList; }
class BytesList;
namespace capi { struct Csr; }
class Csr;
} // namespace _native



namespace _native {
namespace capi {
    struct Csr;
} // namespace capi
} // namespace

namespace _native {
class Csr {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::Csr>, std::unique_ptr<_native::BindingError>> from_der(_native::diplomat::span<const uint8_t> der);

  inline _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>> to_der() const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> to_pem() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> to_pem_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> to_base64() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> to_base64_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> to_pem_base64() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> to_pem_base64_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> subject_string() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> subject_string_write(W& writeable_output) const;

  inline _native::diplomat::result<std::unique_ptr<_native::BytesList>, std::unique_ptr<_native::BindingError>> extension_values_der() const;

    inline const _native::capi::Csr* AsFFI() const;
    inline _native::capi::Csr* AsFFI();
    inline static const _native::Csr* FromFFI(const _native::capi::Csr* ptr);
    inline static _native::Csr* FromFFI(_native::capi::Csr* ptr);
    inline static void operator delete(void* ptr);
private:
    Csr() = delete;
    Csr(const _native::Csr&) = delete;
    Csr(_native::Csr&&) noexcept = delete;
    Csr operator=(const _native::Csr&) = delete;
    Csr operator=(_native::Csr&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_Csr_D_HPP
