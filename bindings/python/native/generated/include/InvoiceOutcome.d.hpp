#ifndef _NATIVE_InvoiceOutcome_D_HPP
#define _NATIVE_InvoiceOutcome_D_HPP

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
    enum InvoiceOutcome {
      InvoiceOutcome_Unknown = 0,
      InvoiceOutcome_Accepted = 1,
      InvoiceOutcome_Rejected = 2,
    };

    typedef struct InvoiceOutcome_option {union { InvoiceOutcome ok; }; bool is_ok; } InvoiceOutcome_option;
} // namespace capi
} // namespace

namespace _native {
class InvoiceOutcome {
public:
    enum Value {
        Unknown = 0,
        Accepted = 1,
        Rejected = 2,
    };

    InvoiceOutcome(): value(Value::Unknown) {}

    // Implicit conversions between enum and ::Value
    constexpr InvoiceOutcome(Value v) : value(v) {}
    constexpr operator Value() const { return value; }
    // Prevent usage as boolean value
    explicit operator bool() const = delete;

    inline _native::capi::InvoiceOutcome AsFFI() const;
    inline static _native::InvoiceOutcome FromFFI(_native::capi::InvoiceOutcome c_enum);
private:
    Value value;
};

} // namespace
#endif // _NATIVE_InvoiceOutcome_D_HPP
