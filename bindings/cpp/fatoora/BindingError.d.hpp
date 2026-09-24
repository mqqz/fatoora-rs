#ifndef fatoora_BindingError_D_HPP
#define fatoora_BindingError_D_HPP

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
    struct BindingError;
} // namespace capi
} // namespace

namespace fatoora {
class BindingError {
public:

  inline int32_t code() const;

  inline std::string message() const;
  template<typename W>
  inline void message_write(W& writeable_output) const;

  inline std::string details_json() const;
  template<typename W>
  inline void details_json_write(W& writeable_output) const;

    inline const fatoora::capi::BindingError* AsFFI() const;
    inline fatoora::capi::BindingError* AsFFI();
    inline static const fatoora::BindingError* FromFFI(const fatoora::capi::BindingError* ptr);
    inline static fatoora::BindingError* FromFFI(fatoora::capi::BindingError* ptr);
    inline static void operator delete(void* ptr);
private:
    BindingError() = delete;
    BindingError(const fatoora::BindingError&) = delete;
    BindingError(fatoora::BindingError&&) noexcept = delete;
    BindingError operator=(const fatoora::BindingError&) = delete;
    BindingError operator=(fatoora::BindingError&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_BindingError_D_HPP
