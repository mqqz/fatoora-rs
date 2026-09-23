#ifndef fatoora_Party_D_HPP
#define fatoora_Party_D_HPP

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
namespace capi { struct Address; }
class Address;
namespace capi { struct BindingError; }
class BindingError;
namespace capi { struct OtherId; }
class OtherId;
namespace capi { struct VatId; }
class VatId;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct Party;
} // namespace capi
} // namespace

namespace fatoora {
class Party {
public:

  inline diplomat::result<std::unique_ptr<fatoora::Address>, std::unique_ptr<fatoora::BindingError>> address() const;

  inline diplomat::result<std::unique_ptr<fatoora::VatId>, std::unique_ptr<fatoora::BindingError>> vat_id() const;

  inline diplomat::result<std::unique_ptr<fatoora::OtherId>, std::unique_ptr<fatoora::BindingError>> other_id() const;

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> name() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> name_write(W& writeable_output) const;

    inline const fatoora::capi::Party* AsFFI() const;
    inline fatoora::capi::Party* AsFFI();
    inline static const fatoora::Party* FromFFI(const fatoora::capi::Party* ptr);
    inline static fatoora::Party* FromFFI(fatoora::capi::Party* ptr);
    inline static void operator delete(void* ptr);
private:
    Party() = delete;
    Party(const fatoora::Party&) = delete;
    Party(fatoora::Party&&) noexcept = delete;
    Party operator=(const fatoora::Party&) = delete;
    Party operator=(fatoora::Party&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_Party_D_HPP
