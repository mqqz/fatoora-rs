#ifndef fatoora_BytesList_D_HPP
#define fatoora_BytesList_D_HPP

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
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct BytesList;
} // namespace capi
} // namespace

namespace fatoora {
class BytesList {
public:

  inline size_t len() const;

  inline bool is_empty() const;

  inline diplomat::result<std::unique_ptr<fatoora::Bytes>, std::unique_ptr<fatoora::BindingError>> get(size_t index) const;

    inline const fatoora::capi::BytesList* AsFFI() const;
    inline fatoora::capi::BytesList* AsFFI();
    inline static const fatoora::BytesList* FromFFI(const fatoora::capi::BytesList* ptr);
    inline static fatoora::BytesList* FromFFI(fatoora::capi::BytesList* ptr);
    inline static void operator delete(void* ptr);
private:
    BytesList() = delete;
    BytesList(const fatoora::BytesList&) = delete;
    BytesList(fatoora::BytesList&&) noexcept = delete;
    BytesList operator=(const fatoora::BytesList&) = delete;
    BytesList operator=(fatoora::BytesList&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_BytesList_D_HPP
