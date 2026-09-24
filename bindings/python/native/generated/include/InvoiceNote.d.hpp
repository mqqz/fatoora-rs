#ifndef _NATIVE_InvoiceNote_D_HPP
#define _NATIVE_InvoiceNote_D_HPP

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
    struct InvoiceNote;
} // namespace capi
} // namespace

namespace _native {
class InvoiceNote {
public:

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> language() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> language_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> text() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> text_write(W& writeable_output) const;

    inline const _native::capi::InvoiceNote* AsFFI() const;
    inline _native::capi::InvoiceNote* AsFFI();
    inline static const _native::InvoiceNote* FromFFI(const _native::capi::InvoiceNote* ptr);
    inline static _native::InvoiceNote* FromFFI(_native::capi::InvoiceNote* ptr);
    inline static void operator delete(void* ptr);
private:
    InvoiceNote() = delete;
    InvoiceNote(const _native::InvoiceNote&) = delete;
    InvoiceNote(_native::InvoiceNote&&) noexcept = delete;
    InvoiceNote operator=(const _native::InvoiceNote&) = delete;
    InvoiceNote operator=(_native::InvoiceNote&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_InvoiceNote_D_HPP
