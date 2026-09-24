#ifndef fatoora_VatId_D_HPP
#define fatoora_VatId_D_HPP

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
    struct VatId;
} // namespace capi
} // namespace

namespace fatoora {
class VatId {
public:

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> value() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> value_write(W& writeable_output) const;

    inline const fatoora::capi::VatId* AsFFI() const;
    inline fatoora::capi::VatId* AsFFI();
    inline static const fatoora::VatId* FromFFI(const fatoora::capi::VatId* ptr);
    inline static fatoora::VatId* FromFFI(fatoora::capi::VatId* ptr);
    inline static void operator delete(void* ptr);
private:
    VatId() = delete;
    VatId(const fatoora::VatId&) = delete;
    VatId(fatoora::VatId&&) noexcept = delete;
    VatId operator=(const fatoora::VatId&) = delete;
    VatId operator=(fatoora::VatId&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_VatId_D_HPP
