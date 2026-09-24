#ifndef _NATIVE_FinalizedInvoice_D_HPP
#define _NATIVE_FinalizedInvoice_D_HPP

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
namespace capi { struct FinalizedInvoice; }
class FinalizedInvoice;
namespace capi { struct InvoiceData; }
class InvoiceData;
namespace capi { struct InvoiceTotals; }
class InvoiceTotals;
} // namespace _native



namespace _native {
namespace capi {
    struct FinalizedInvoice;
} // namespace capi
} // namespace

namespace _native {
class FinalizedInvoice {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>> from_xml(std::string_view value);

  inline static _native::diplomat::result<std::unique_ptr<_native::FinalizedInvoice>, std::unique_ptr<_native::BindingError>> from_file(std::string_view value);

  inline _native::diplomat::result<std::unique_ptr<_native::InvoiceData>, std::unique_ptr<_native::BindingError>> data() const;

  inline _native::diplomat::result<std::unique_ptr<_native::InvoiceTotals>, std::unique_ptr<_native::BindingError>> totals() const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> hash_base64() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> hash_base64_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> xml() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> xml_write(W& writeable_output) const;

    inline const _native::capi::FinalizedInvoice* AsFFI() const;
    inline _native::capi::FinalizedInvoice* AsFFI();
    inline static const _native::FinalizedInvoice* FromFFI(const _native::capi::FinalizedInvoice* ptr);
    inline static _native::FinalizedInvoice* FromFFI(_native::capi::FinalizedInvoice* ptr);
    inline static void operator delete(void* ptr);
private:
    FinalizedInvoice() = delete;
    FinalizedInvoice(const _native::FinalizedInvoice&) = delete;
    FinalizedInvoice(_native::FinalizedInvoice&&) noexcept = delete;
    FinalizedInvoice operator=(const _native::FinalizedInvoice&) = delete;
    FinalizedInvoice operator=(_native::FinalizedInvoice&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_FinalizedInvoice_D_HPP
