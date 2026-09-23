#ifndef fatoora_InvoiceOutcome_D_HPP
#define fatoora_InvoiceOutcome_D_HPP

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
    enum InvoiceOutcome {
      InvoiceOutcome_Unknown = 0,
      InvoiceOutcome_Accepted = 1,
      InvoiceOutcome_Rejected = 2,
    };

    typedef struct InvoiceOutcome_option {union { InvoiceOutcome ok; }; bool is_ok; } InvoiceOutcome_option;
} // namespace capi
} // namespace

namespace fatoora {
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

    inline fatoora::capi::InvoiceOutcome AsFFI() const;
    inline static fatoora::InvoiceOutcome FromFFI(fatoora::capi::InvoiceOutcome c_enum);
private:
    Value value;
};

} // namespace
#endif // fatoora_InvoiceOutcome_D_HPP
