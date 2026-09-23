#ifndef _NATIVE_Signer_D_HPP
#define _NATIVE_Signer_D_HPP

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
namespace capi { struct Bytes; }
class Bytes;
namespace capi { struct FinalizedInvoice; }
class FinalizedInvoice;
namespace capi { struct SignedInvoice; }
class SignedInvoice;
namespace capi { struct Signer; }
class Signer;
} // namespace _native



namespace _native {
namespace capi {
    struct Signer;
} // namespace capi
} // namespace

namespace _native {
class Signer {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::Signer>, std::unique_ptr<_native::BindingError>> from_pem(std::string_view cert_pem, std::string_view key_pem);

  inline static _native::diplomat::result<std::unique_ptr<_native::Signer>, std::unique_ptr<_native::BindingError>> from_der(_native::diplomat::span<const uint8_t> cert_der, _native::diplomat::span<const uint8_t> key_der);

  inline _native::diplomat::result<std::unique_ptr<_native::Bytes>, std::unique_ptr<_native::BindingError>> certificate_der() const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> certificate_pem() const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> certificate_pem_write(W& writeable_output) const;

  inline _native::diplomat::result<std::unique_ptr<_native::SignedInvoice>, std::unique_ptr<_native::BindingError>> sign(_native::FinalizedInvoice& invoice) const;

  inline _native::diplomat::result<std::string, std::unique_ptr<_native::BindingError>> sign_xml(std::string_view xml) const;
  template<typename W>
  inline _native::diplomat::result<std::monostate, std::unique_ptr<_native::BindingError>> sign_xml_write(std::string_view xml, W& writeable_output) const;

    inline const _native::capi::Signer* AsFFI() const;
    inline _native::capi::Signer* AsFFI();
    inline static const _native::Signer* FromFFI(const _native::capi::Signer* ptr);
    inline static _native::Signer* FromFFI(_native::capi::Signer* ptr);
    inline static void operator delete(void* ptr);
private:
    Signer() = delete;
    Signer(const _native::Signer&) = delete;
    Signer(_native::Signer&&) noexcept = delete;
    Signer operator=(const _native::Signer&) = delete;
    Signer operator=(_native::Signer&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_Signer_D_HPP
