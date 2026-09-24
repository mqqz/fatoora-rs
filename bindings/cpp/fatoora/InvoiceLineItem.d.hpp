#ifndef fatoora_InvoiceLineItem_D_HPP
#define fatoora_InvoiceLineItem_D_HPP

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
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct InvoiceLineItem;
} // namespace capi
} // namespace

namespace fatoora {
class InvoiceLineItem {
public:

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> description() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> description_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> unit_code() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> unit_code_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> quantity() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> quantity_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> unit_price() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> unit_price_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> total_amount() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> total_amount_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> vat_rate() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> vat_rate_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> vat_amount() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> vat_amount_write(W& writeable_output) const;

  inline uint8_t vat_category() const;

    inline const fatoora::capi::InvoiceLineItem* AsFFI() const;
    inline fatoora::capi::InvoiceLineItem* AsFFI();
    inline static const fatoora::InvoiceLineItem* FromFFI(const fatoora::capi::InvoiceLineItem* ptr);
    inline static fatoora::InvoiceLineItem* FromFFI(fatoora::capi::InvoiceLineItem* ptr);
    inline static void operator delete(void* ptr);
private:
    InvoiceLineItem() = delete;
    InvoiceLineItem(const fatoora::InvoiceLineItem&) = delete;
    InvoiceLineItem(fatoora::InvoiceLineItem&&) noexcept = delete;
    InvoiceLineItem operator=(const fatoora::InvoiceLineItem&) = delete;
    InvoiceLineItem operator=(fatoora::InvoiceLineItem&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_InvoiceLineItem_D_HPP
