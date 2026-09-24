#ifndef fatoora_Csr_D_HPP
#define fatoora_Csr_D_HPP

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
namespace capi { struct BytesList; }
class BytesList;
namespace capi { struct Csr; }
class Csr;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct Csr;
} // namespace capi
} // namespace

namespace fatoora {
class Csr {
public:

  inline static diplomat::result<std::unique_ptr<fatoora::Csr>, std::unique_ptr<fatoora::BindingError>> from_der(diplomat::span<const uint8_t> der);

  inline diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>> to_der() const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> to_pem() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> to_pem_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> to_base64() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> to_base64_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> to_pem_base64() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> to_pem_base64_write(W& writeable_output) const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> subject_string() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> subject_string_write(W& writeable_output) const;

  inline diplomat::result<std::unique_ptr<fatoora::BytesList>, std::unique_ptr<fatoora::BindingError>> extension_values_der() const;

    inline const fatoora::capi::Csr* AsFFI() const;
    inline fatoora::capi::Csr* AsFFI();
    inline static const fatoora::Csr* FromFFI(const fatoora::capi::Csr* ptr);
    inline static fatoora::Csr* FromFFI(fatoora::capi::Csr* ptr);
    inline static void operator delete(void* ptr);
private:
    Csr() = delete;
    Csr(const fatoora::Csr&) = delete;
    Csr(fatoora::Csr&&) noexcept = delete;
    Csr operator=(const fatoora::Csr&) = delete;
    Csr operator=(fatoora::Csr&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_Csr_D_HPP
