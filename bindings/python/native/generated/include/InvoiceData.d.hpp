#ifndef _NATIVE_InvoiceData_D_HPP
#define _NATIVE_InvoiceData_D_HPP

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
namespace capi { struct InvoiceLineItem; }
class InvoiceLineItem;
namespace capi { struct InvoiceNote; }
class InvoiceNote;
namespace capi { struct OriginalInvoiceRef; }
class OriginalInvoiceRef;
namespace capi { struct Party; }
class Party;
namespace capi { struct Text; }
class Text;
} // namespace _native



namespace _native {
namespace capi {
    struct InvoiceData;
} // namespace capi
} // namespace

namespace _native {
class InvoiceData {
public:

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> id() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> id_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> uuid() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> uuid_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> previous_invoice_hash() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> previous_invoice_hash_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> payment_means_code() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> payment_means_code_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> currency() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> currency_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> issue_datetime() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> issue_datetime_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> invoice_level_charge() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> invoice_level_charge_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> invoice_level_discount() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> invoice_level_discount_write(W& writeable_output) const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> allowance_reason() const;

  inline uint64_t invoice_counter() const;

  inline uint8_t vat_category() const;

  inline uint8_t flags_raw() const;

  inline uint8_t invoice_type_kind() const;

  inline uint8_t invoice_sub_type() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Party>, std::unique_ptr<_native::BindingError>> seller() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Party>, std::unique_ptr<_native::BindingError>> buyer() const;

  inline _native::diplomat::result<std::unique_ptr<_native::InvoiceNote>, std::unique_ptr<_native::BindingError>> note() const;

  inline size_t line_items_len() const;

  inline _native::diplomat::result<std::unique_ptr<_native::InvoiceLineItem>, std::unique_ptr<_native::BindingError>> line_item(size_t index) const;

  inline _native::diplomat::result<std::unique_ptr<_native::OriginalInvoiceRef>, std::unique_ptr<_native::BindingError>> original_invoice_ref() const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> original_invoice_reason() const;

    inline const _native::capi::InvoiceData* AsFFI() const;
    inline _native::capi::InvoiceData* AsFFI();
    inline static const _native::InvoiceData* FromFFI(const _native::capi::InvoiceData* ptr);
    inline static _native::InvoiceData* FromFFI(_native::capi::InvoiceData* ptr);
    inline static void operator delete(void* ptr);
private:
    InvoiceData() = delete;
    InvoiceData(const _native::InvoiceData&) = delete;
    InvoiceData(_native::InvoiceData&&) noexcept = delete;
    InvoiceData operator=(const _native::InvoiceData&) = delete;
    InvoiceData operator=(_native::InvoiceData&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_InvoiceData_D_HPP
