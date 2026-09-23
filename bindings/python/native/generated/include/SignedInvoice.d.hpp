#ifndef _NATIVE_SignedInvoice_D_HPP
#define _NATIVE_SignedInvoice_D_HPP

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
namespace capi { struct InvoiceData; }
class InvoiceData;
namespace capi { struct InvoiceTotals; }
class InvoiceTotals;
namespace capi { struct SignedInvoice; }
class SignedInvoice;
namespace capi { struct Text; }
class Text;
} // namespace _native



namespace _native {
namespace capi {
    struct SignedInvoice;
} // namespace capi
} // namespace

namespace _native {
class SignedInvoice {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::SignedInvoice>, std::unique_ptr<_native::BindingError>> from_xml(std::string_view value);

  inline static _native::diplomat::result<std::unique_ptr<_native::SignedInvoice>, std::unique_ptr<_native::BindingError>> from_file(std::string_view value);

  inline _native::diplomat::result<std::unique_ptr<_native::InvoiceData>, std::unique_ptr<_native::BindingError>> data() const;

  inline _native::diplomat::result<std::unique_ptr<_native::InvoiceTotals>, std::unique_ptr<_native::BindingError>> totals() const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> hash_base64() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> hash_base64_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> xml() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> xml_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> qr_code() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> qr_code_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> signature() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> signature_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> public_key() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> public_key_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> invoice_hash() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> invoice_hash_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> to_xml_base64() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> to_xml_base64_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> issuer() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> issuer_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> serial() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> serial_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> cert_hash() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> cert_hash_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> signed_props_hash() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> signed_props_hash_write(W& writeable_output) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> signing_time() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> signing_time_write(W& writeable_output) const;

  inline _native::diplomat::result<std::unique_ptr<_native::Text>, std::unique_ptr<_native::BindingError>> zatca_key_signature() const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> into_xml();
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> into_xml_write(W& writeable_output);

    inline const _native::capi::SignedInvoice* AsFFI() const;
    inline _native::capi::SignedInvoice* AsFFI();
    inline static const _native::SignedInvoice* FromFFI(const _native::capi::SignedInvoice* ptr);
    inline static _native::SignedInvoice* FromFFI(_native::capi::SignedInvoice* ptr);
    inline static void operator delete(void* ptr);
private:
    SignedInvoice() = delete;
    SignedInvoice(const _native::SignedInvoice&) = delete;
    SignedInvoice(_native::SignedInvoice&&) noexcept = delete;
    SignedInvoice operator=(const _native::SignedInvoice&) = delete;
    SignedInvoice operator=(_native::SignedInvoice&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_SignedInvoice_D_HPP
