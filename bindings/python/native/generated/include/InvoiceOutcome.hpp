#ifndef _NATIVE_InvoiceOutcome_HPP
#define _NATIVE_InvoiceOutcome_HPP

#include "InvoiceOutcome.d.hpp"

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
namespace capi {

} // namespace capi
} // namespace

inline _native::capi::InvoiceOutcome _native::InvoiceOutcome::AsFFI() const {
    return static_cast<_native::capi::InvoiceOutcome>(value);
}

inline _native::InvoiceOutcome _native::InvoiceOutcome::FromFFI(_native::capi::InvoiceOutcome c_enum) {
    switch (c_enum) {
        case _native::capi::InvoiceOutcome_Unknown:
        case _native::capi::InvoiceOutcome_Accepted:
        case _native::capi::InvoiceOutcome_Rejected:
            return static_cast<_native::InvoiceOutcome::Value>(c_enum);
        default:
            std::abort();
    }
}
#endif // _NATIVE_InvoiceOutcome_HPP
