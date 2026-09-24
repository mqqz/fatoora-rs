#ifndef _NATIVE_OriginalInvoiceRef_D_HPP
#define _NATIVE_OriginalInvoiceRef_D_HPP

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
    struct OriginalInvoiceRef;
} // namespace capi
} // namespace

namespace _native {
class OriginalInvoiceRef {
public:

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> id() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> id_write(W& writeable_output) const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> uuid() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> issue_date() const;

    inline const _native::capi::OriginalInvoiceRef* AsFFI() const;
    inline _native::capi::OriginalInvoiceRef* AsFFI();
    inline static const _native::OriginalInvoiceRef* FromFFI(const _native::capi::OriginalInvoiceRef* ptr);
    inline static _native::OriginalInvoiceRef* FromFFI(_native::capi::OriginalInvoiceRef* ptr);
    inline static void operator delete(void* ptr);
private:
    OriginalInvoiceRef() = delete;
    OriginalInvoiceRef(const _native::OriginalInvoiceRef&) = delete;
    OriginalInvoiceRef(_native::OriginalInvoiceRef&&) noexcept = delete;
    OriginalInvoiceRef operator=(const _native::OriginalInvoiceRef&) = delete;
    OriginalInvoiceRef operator=(_native::OriginalInvoiceRef&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_OriginalInvoiceRef_D_HPP
