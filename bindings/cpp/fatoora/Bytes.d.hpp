#ifndef fatoora_Bytes_D_HPP
#define fatoora_Bytes_D_HPP

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
namespace capi {
    struct Bytes;
} // namespace capi
} // namespace

namespace fatoora {
class Bytes {
public:

  /**
   * The view is valid while this immutable owner remains alive.
   */
  inline diplomat::span<const uint8_t> as_slice() const DIPLOMAT_LIFETIME_BOUND;

    inline const fatoora::capi::Bytes* AsFFI() const;
    inline fatoora::capi::Bytes* AsFFI();
    inline static const fatoora::Bytes* FromFFI(const fatoora::capi::Bytes* ptr);
    inline static fatoora::Bytes* FromFFI(fatoora::capi::Bytes* ptr);
    inline static void operator delete(void* ptr);
private:
    Bytes() = delete;
    Bytes(const fatoora::Bytes&) = delete;
    Bytes(fatoora::Bytes&&) noexcept = delete;
    Bytes operator=(const fatoora::Bytes&) = delete;
    Bytes operator=(fatoora::Bytes&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_Bytes_D_HPP
