#ifndef _NATIVE_Config_D_HPP
#define _NATIVE_Config_D_HPP

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
namespace capi { struct Config; }
class Config;
} // namespace _native



namespace _native {
namespace capi {
    struct Config;
} // namespace capi
} // namespace

namespace _native {
class Config {
public:

  inline static _native::diplomat::result<std::unique_ptr<_native::Config>, std::unique_ptr<_native::BindingError>> new_(uint8_t env);

  inline uint8_t env() const;

    inline const _native::capi::Config* AsFFI() const;
    inline _native::capi::Config* AsFFI();
    inline static const _native::Config* FromFFI(const _native::capi::Config* ptr);
    inline static _native::Config* FromFFI(_native::capi::Config* ptr);
    inline static void operator delete(void* ptr);
private:
    Config() = delete;
    Config(const _native::Config&) = delete;
    Config(_native::Config&&) noexcept = delete;
    Config operator=(const _native::Config&) = delete;
    Config operator=(_native::Config&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // _NATIVE_Config_D_HPP
