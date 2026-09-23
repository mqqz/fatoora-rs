#ifndef _NATIVE_InvoiceTotals_D_HPP
#define _NATIVE_InvoiceTotals_D_HPP

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
    struct InvoiceTotals;
} // namespace capi
} // namespace

namespace _native {
class InvoiceTotals {
public:

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> tax_inclusive() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> tax_inclusive_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> tax_amount() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> tax_amount_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> line_extension() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> line_extension_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> allowance_total() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> allowance_total_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> charge_total() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> charge_total_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> taxable_amount() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> taxable_amount_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> prepaid_amount() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> prepaid_amount_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> payable_rounding_amount() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> payable_rounding_amount_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> payable_amount() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> payable_amount_write(W& writeable_output) const;

    inline const _native::capi::InvoiceTotals* AsFFI() const;
    inline _native::capi::InvoiceTotals* AsFFI();
    inline static const _native::InvoiceTotals* FromFFI(const _native::capi::InvoiceTotals* ptr);
    inline static _native::InvoiceTotals* FromFFI(_native::capi::InvoiceTotals* ptr);
    inline static void operator delete(void* ptr);
private:
    InvoiceTotals() = delete;
    InvoiceTotals(const _native::InvoiceTotals&) = delete;
    InvoiceTotals(_native::InvoiceTotals&&) noexcept = delete;
    InvoiceTotals operator=(const _native::InvoiceTotals&) = delete;
    InvoiceTotals operator=(_native::InvoiceTotals&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_InvoiceTotals_D_HPP
