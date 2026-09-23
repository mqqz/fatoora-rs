#ifndef fatoora_Text_D_HPP
#define fatoora_Text_D_HPP

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
    struct Text;
} // namespace capi
} // namespace

namespace fatoora {
class Text {
public:

  inline diplomat::result<std::string, std::unique_ptr<fatoora::BindingError>> value() const;
  template<typename W>
  inline diplomat::result<std::monostate, std::unique_ptr<fatoora::BindingError>> value_write(W& writeable_output) const;

    inline const fatoora::capi::Text* AsFFI() const;
    inline fatoora::capi::Text* AsFFI();
    inline static const fatoora::Text* FromFFI(const fatoora::capi::Text* ptr);
    inline static fatoora::Text* FromFFI(fatoora::capi::Text* ptr);
    inline static void operator delete(void* ptr);
private:
    Text() = delete;
    Text(const fatoora::Text&) = delete;
    Text(fatoora::Text&&) noexcept = delete;
    Text operator=(const fatoora::Text&) = delete;
    Text operator=(fatoora::Text&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_Text_D_HPP
