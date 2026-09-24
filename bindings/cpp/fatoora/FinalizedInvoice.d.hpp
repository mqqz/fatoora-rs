#ifndef fatoora_FinalizedInvoice_D_HPP
#define fatoora_FinalizedInvoice_D_HPP

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
namespace capi { struct FinalizedInvoice; }
class FinalizedInvoice;
namespace capi { struct InvoiceData; }
class InvoiceData;
namespace capi { struct InvoiceTotals; }
class InvoiceTotals;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct FinalizedInvoice;
} // namespace capi
} // namespace

namespace fatoora {
class FinalizedInvoice {
public:

  inline static diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>> from_xml(std::string_view value);

  inline static diplomat::result<std::unique_ptr<fatoora::FinalizedInvoice>, std::unique_ptr<fatoora::BindingError>> from_file(std::string_view value);

  inline diplomat::result<std::unique_ptr<fatoora::InvoiceData>, std::unique_ptr<fatoora::BindingError>> data() const;

  inline diplomat::result<std::unique_ptr<fatoora::InvoiceTotals>, std::unique_ptr<fatoora::BindingError>> totals() const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> hash_base64() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> hash_base64_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> xml() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> xml_write(W& writeable_output) const;

    inline const fatoora::capi::FinalizedInvoice* AsFFI() const;
    inline fatoora::capi::FinalizedInvoice* AsFFI();
    inline static const fatoora::FinalizedInvoice* FromFFI(const fatoora::capi::FinalizedInvoice* ptr);
    inline static fatoora::FinalizedInvoice* FromFFI(fatoora::capi::FinalizedInvoice* ptr);
    inline static void operator delete(void* ptr);
private:
    FinalizedInvoice() = delete;
    FinalizedInvoice(const fatoora::FinalizedInvoice&) = delete;
    FinalizedInvoice(fatoora::FinalizedInvoice&&) noexcept = delete;
    FinalizedInvoice operator=(const fatoora::FinalizedInvoice&) = delete;
    FinalizedInvoice operator=(fatoora::FinalizedInvoice&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_FinalizedInvoice_D_HPP
