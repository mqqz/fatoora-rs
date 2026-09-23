#ifndef fatoora_InvoiceData_D_HPP
#define fatoora_InvoiceData_D_HPP

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "../diplomat_runtime.hpp"

namespace fatoora {
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
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct InvoiceData;
} // namespace capi
} // namespace

namespace fatoora {
class InvoiceData {
public:

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> id() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> id_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> uuid() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> uuid_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> previous_invoice_hash() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> previous_invoice_hash_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> payment_means_code() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> payment_means_code_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> currency() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> currency_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> issue_datetime() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> issue_datetime_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> invoice_level_charge() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> invoice_level_charge_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> invoice_level_discount() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> invoice_level_discount_write(W& writeable_output) const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> allowance_reason() const;

  inline uint64_t invoice_counter() const;

  inline uint8_t vat_category() const;

  inline uint8_t flags_raw() const;

  inline uint8_t invoice_type_kind() const;

  inline uint8_t invoice_sub_type() const;

  inline diplomat::result<std::unique_ptr<fatoora::Party>, std::unique_ptr<fatoora::BindingError>> seller() const;

  inline diplomat::result<std::unique_ptr<fatoora::Party>, std::unique_ptr<fatoora::BindingError>> buyer() const;

  inline diplomat::result<std::unique_ptr<fatoora::InvoiceNote>, std::unique_ptr<fatoora::BindingError>> note() const;

  inline size_t line_items_len() const;

  inline diplomat::result<std::unique_ptr<fatoora::InvoiceLineItem>, std::unique_ptr<fatoora::BindingError>> line_item(size_t index) const;

  inline diplomat::result<std::unique_ptr<fatoora::OriginalInvoiceRef>, std::unique_ptr<fatoora::BindingError>> original_invoice_ref() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> original_invoice_reason() const;

    inline const fatoora::capi::InvoiceData* AsFFI() const;
    inline fatoora::capi::InvoiceData* AsFFI();
    inline static const fatoora::InvoiceData* FromFFI(const fatoora::capi::InvoiceData* ptr);
    inline static fatoora::InvoiceData* FromFFI(fatoora::capi::InvoiceData* ptr);
    inline static void operator delete(void* ptr);
private:
    InvoiceData() = delete;
    InvoiceData(const fatoora::InvoiceData&) = delete;
    InvoiceData(fatoora::InvoiceData&&) noexcept = delete;
    InvoiceData operator=(const fatoora::InvoiceData&) = delete;
    InvoiceData operator=(fatoora::InvoiceData&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_InvoiceData_D_HPP
