#ifndef fatoora_InvoiceNote_D_HPP
#define fatoora_InvoiceNote_D_HPP

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
    struct InvoiceNote;
} // namespace capi
} // namespace

namespace fatoora {
class InvoiceNote {
public:

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> language() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> language_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> text() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> text_write(W& writeable_output) const;

    inline const fatoora::capi::InvoiceNote* AsFFI() const;
    inline fatoora::capi::InvoiceNote* AsFFI();
    inline static const fatoora::InvoiceNote* FromFFI(const fatoora::capi::InvoiceNote* ptr);
    inline static fatoora::InvoiceNote* FromFFI(fatoora::capi::InvoiceNote* ptr);
    inline static void operator delete(void* ptr);
private:
    InvoiceNote() = delete;
    InvoiceNote(const fatoora::InvoiceNote&) = delete;
    InvoiceNote(fatoora::InvoiceNote&&) noexcept = delete;
    InvoiceNote operator=(const fatoora::InvoiceNote&) = delete;
    InvoiceNote operator=(fatoora::InvoiceNote&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_InvoiceNote_D_HPP
