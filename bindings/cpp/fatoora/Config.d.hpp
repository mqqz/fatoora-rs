#ifndef fatoora_Config_D_HPP
#define fatoora_Config_D_HPP

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
namespace capi { struct Config; }
class Config;
} // namespace fatoora




namespace fatoora {
namespace capi {
    struct Config;
} // namespace capi
} // namespace

namespace fatoora {
class Config {
public:

  inline static diplomat::result<std::unique_ptr<fatoora::Config>, std::unique_ptr<fatoora::BindingError>> new_(uint8_t env);

  inline uint8_t env() const;

    inline const fatoora::capi::Config* AsFFI() const;
    inline fatoora::capi::Config* AsFFI();
    inline static const fatoora::Config* FromFFI(const fatoora::capi::Config* ptr);
    inline static fatoora::Config* FromFFI(fatoora::capi::Config* ptr);
    inline static void operator delete(void* ptr);
private:
    Config() = delete;
    Config(const fatoora::Config&) = delete;
    Config(fatoora::Config&&) noexcept = delete;
    Config operator=(const fatoora::Config&) = delete;
    Config operator=(fatoora::Config&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // fatoora_Config_D_HPP
