#ifndef fatoora_InvoiceTotals_D_HPP
#define fatoora_InvoiceTotals_D_HPP

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
    struct InvoiceTotals;
} // namespace capi
} // namespace

namespace fatoora {
class InvoiceTotals {
public:

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> tax_inclusive() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> tax_inclusive_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> tax_amount() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> tax_amount_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> line_extension() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> line_extension_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> allowance_total() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> allowance_total_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> charge_total() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> charge_total_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> taxable_amount() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> taxable_amount_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> prepaid_amount() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> prepaid_amount_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> payable_rounding_amount() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> payable_rounding_amount_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> payable_amount() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> payable_amount_write(W& writeable_output) const;

    inline const fatoora::capi::InvoiceTotals* AsFFI() const;
    inline fatoora::capi::InvoiceTotals* AsFFI();
    inline static const fatoora::InvoiceTotals* FromFFI(const fatoora::capi::InvoiceTotals* ptr);
    inline static fatoora::InvoiceTotals* FromFFI(fatoora::capi::InvoiceTotals* ptr);
    inline static void operator delete(void* ptr);
private:
    InvoiceTotals() = delete;
    InvoiceTotals(const fatoora::InvoiceTotals&) = delete;
    InvoiceTotals(fatoora::InvoiceTotals&&) noexcept = delete;
    InvoiceTotals operator=(const fatoora::InvoiceTotals&) = delete;
    InvoiceTotals operator=(fatoora::InvoiceTotals&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_InvoiceTotals_D_HPP
