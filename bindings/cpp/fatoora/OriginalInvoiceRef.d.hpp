#ifndef fatoora_OriginalInvoiceRef_D_HPP
#define fatoora_OriginalInvoiceRef_D_HPP

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
namespace capi { struct Text; }
class Text;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct OriginalInvoiceRef;
} // namespace capi
} // namespace

namespace fatoora {
class OriginalInvoiceRef {
public:

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> id() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> id_write(W& writeable_output) const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> uuid() const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> issue_date() const;

    inline const fatoora::capi::OriginalInvoiceRef* AsFFI() const;
    inline fatoora::capi::OriginalInvoiceRef* AsFFI();
    inline static const fatoora::OriginalInvoiceRef* FromFFI(const fatoora::capi::OriginalInvoiceRef* ptr);
    inline static fatoora::OriginalInvoiceRef* FromFFI(fatoora::capi::OriginalInvoiceRef* ptr);
    inline static void operator delete(void* ptr);
private:
    OriginalInvoiceRef() = delete;
    OriginalInvoiceRef(const fatoora::OriginalInvoiceRef&) = delete;
    OriginalInvoiceRef(fatoora::OriginalInvoiceRef&&) noexcept = delete;
    OriginalInvoiceRef operator=(const fatoora::OriginalInvoiceRef&) = delete;
    OriginalInvoiceRef operator=(fatoora::OriginalInvoiceRef&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_OriginalInvoiceRef_D_HPP
