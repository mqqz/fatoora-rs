#ifndef fatoora_InvoiceOutcome_HPP
#define fatoora_InvoiceOutcome_HPP

#include "InvoiceOutcome.d.hpp"

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

} // namespace capi
} // namespace

inline fatoora::capi::InvoiceOutcome fatoora::InvoiceOutcome::AsFFI() const {
    return static_cast<fatoora::capi::InvoiceOutcome>(value);
}

inline fatoora::InvoiceOutcome fatoora::InvoiceOutcome::FromFFI(fatoora::capi::InvoiceOutcome c_enum) {
    switch (c_enum) {
        case fatoora::capi::InvoiceOutcome_Unknown:
        case fatoora::capi::InvoiceOutcome_Accepted:
        case fatoora::capi::InvoiceOutcome_Rejected:
            return static_cast<fatoora::InvoiceOutcome::Value>(c_enum);
        default:
            std::abort();
    }
}
#endif // fatoora_InvoiceOutcome_HPP
