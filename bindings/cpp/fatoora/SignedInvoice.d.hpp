#ifndef fatoora_SignedInvoice_D_HPP
#define fatoora_SignedInvoice_D_HPP

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
namespace capi { struct InvoiceData; }
class InvoiceData;
namespace capi { struct InvoiceTotals; }
class InvoiceTotals;
namespace capi { struct SignedInvoice; }
class SignedInvoice;
namespace capi { struct Text; }
class Text;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct SignedInvoice;
} // namespace capi
} // namespace

namespace fatoora {
class SignedInvoice {
public:

  inline static diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>> from_xml(std::string_view value);

  inline static diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>> from_file(std::string_view value);

  inline diplomat::result<std::unique_ptr<fatoora::InvoiceData>, std::unique_ptr<fatoora::BindingError>> data() const;

  inline diplomat::result<std::unique_ptr<fatoora::InvoiceTotals>, std::unique_ptr<fatoora::BindingError>> totals() const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> hash_base64() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> hash_base64_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> xml() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> xml_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> qr_code() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> qr_code_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> signature() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> signature_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> public_key() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> public_key_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> invoice_hash() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> invoice_hash_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> to_xml_base64() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> to_xml_base64_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> issuer() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> issuer_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> serial() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> serial_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> cert_hash() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> cert_hash_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> signed_props_hash() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> signed_props_hash_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> signing_time() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> signing_time_write(W& writeable_output) const;

  inline diplomat::result<std::unique_ptr<fatoora::Text>, std::unique_ptr<fatoora::BindingError>> zatca_key_signature() const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> into_xml();
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> into_xml_write(W& writeable_output);

    inline const fatoora::capi::SignedInvoice* AsFFI() const;
    inline fatoora::capi::SignedInvoice* AsFFI();
    inline static const fatoora::SignedInvoice* FromFFI(const fatoora::capi::SignedInvoice* ptr);
    inline static fatoora::SignedInvoice* FromFFI(fatoora::capi::SignedInvoice* ptr);
    inline static void operator delete(void* ptr);
private:
    SignedInvoice() = delete;
    SignedInvoice(const fatoora::SignedInvoice&) = delete;
    SignedInvoice(fatoora::SignedInvoice&&) noexcept = delete;
    SignedInvoice operator=(const fatoora::SignedInvoice&) = delete;
    SignedInvoice operator=(fatoora::SignedInvoice&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_SignedInvoice_D_HPP
