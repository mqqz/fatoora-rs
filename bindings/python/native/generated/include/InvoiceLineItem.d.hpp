#ifndef _NATIVE_InvoiceLineItem_D_HPP
#define _NATIVE_InvoiceLineItem_D_HPP

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
    struct InvoiceLineItem;
} // namespace capi
} // namespace

namespace _native {
class InvoiceLineItem {
public:

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> description() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> description_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> unit_code() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> unit_code_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> quantity() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> quantity_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> unit_price() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> unit_price_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> total_amount() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> total_amount_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> vat_rate() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> vat_rate_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> vat_amount() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> vat_amount_write(W& writeable_output) const;

  inline uint8_t vat_category() const;

    inline const _native::capi::InvoiceLineItem* AsFFI() const;
    inline _native::capi::InvoiceLineItem* AsFFI();
    inline static const _native::InvoiceLineItem* FromFFI(const _native::capi::InvoiceLineItem* ptr);
    inline static _native::InvoiceLineItem* FromFFI(_native::capi::InvoiceLineItem* ptr);
    inline static void operator delete(void* ptr);
private:
    InvoiceLineItem() = delete;
    InvoiceLineItem(const _native::InvoiceLineItem&) = delete;
    InvoiceLineItem(_native::InvoiceLineItem&&) noexcept = delete;
    InvoiceLineItem operator=(const _native::InvoiceLineItem&) = delete;
    InvoiceLineItem operator=(_native::InvoiceLineItem&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_InvoiceLineItem_D_HPP
