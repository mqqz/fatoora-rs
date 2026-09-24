#ifndef fatoora_SigningKey_D_HPP
#define fatoora_SigningKey_D_HPP

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
namespace capi { struct SigningKey; }
class SigningKey;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct SigningKey;
} // namespace capi
} // namespace

namespace fatoora {
class SigningKey {
public:

  inline static diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>> generate();

  inline static diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>> from_pem(std::string_view pem);

  inline static diplomat::result<std::unique_ptr<fatoora::SigningKey>, std::unique_ptr<fatoora::BindingError>> from_der(diplomat::span<const uint8_t> der);

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> to_pem() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> to_pem_write(W& writeable_output) const;

  inline diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>> to_der() const;

    inline const fatoora::capi::SigningKey* AsFFI() const;
    inline fatoora::capi::SigningKey* AsFFI();
    inline static const fatoora::SigningKey* FromFFI(const fatoora::capi::SigningKey* ptr);
    inline static fatoora::SigningKey* FromFFI(fatoora::capi::SigningKey* ptr);
    inline static void operator delete(void* ptr);
private:
    SigningKey() = delete;
    SigningKey(const fatoora::SigningKey&) = delete;
    SigningKey(fatoora::SigningKey&&) noexcept = delete;
    SigningKey operator=(const fatoora::SigningKey&) = delete;
    SigningKey operator=(fatoora::SigningKey&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_SigningKey_D_HPP
