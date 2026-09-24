#ifndef fatoora_Signer_D_HPP
#define fatoora_Signer_D_HPP

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
namespace capi { struct Bytes; }
class Bytes;
namespace capi { struct FinalizedInvoice; }
class FinalizedInvoice;
namespace capi { struct SignedInvoice; }
class SignedInvoice;
namespace capi { struct Signer; }
class Signer;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct Signer;
} // namespace capi
} // namespace

namespace fatoora {
class Signer {
public:

  inline static diplomat::result<std::unique_ptr<fatoora::Signer>, std::unique_ptr<fatoora::BindingError>> from_pem(std::string_view cert_pem, std::string_view key_pem);

  inline static diplomat::result<std::unique_ptr<fatoora::Signer>, std::unique_ptr<fatoora::BindingError>> from_der(diplomat::span<const uint8_t> cert_der, diplomat::span<const uint8_t> key_der);

  inline diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>> certificate_der() const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> certificate_pem() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> certificate_pem_write(W& writeable_output) const;

  inline diplomat::result<std::unique_ptr<fatoora::SignedInvoice>, std::unique_ptr<fatoora::BindingError>> sign(fatoora::FinalizedInvoice& invoice) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> sign_xml(std::string_view xml) const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> sign_xml_write(std::string_view xml, W& writeable_output) const;

    inline const fatoora::capi::Signer* AsFFI() const;
    inline fatoora::capi::Signer* AsFFI();
    inline static const fatoora::Signer* FromFFI(const fatoora::capi::Signer* ptr);
    inline static fatoora::Signer* FromFFI(fatoora::capi::Signer* ptr);
    inline static void operator delete(void* ptr);
private:
    Signer() = delete;
    Signer(const fatoora::Signer&) = delete;
    Signer(fatoora::Signer&&) noexcept = delete;
    Signer operator=(const fatoora::Signer&) = delete;
    Signer operator=(fatoora::Signer&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_Signer_D_HPP
