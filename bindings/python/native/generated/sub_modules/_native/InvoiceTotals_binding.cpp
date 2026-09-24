#include "diplomat_nanobind_common.hpp"


#include "InvoiceTotals.hpp"

namespace _native {
void add_InvoiceTotals_binding(nb::module_ mod) {
    PyType_Slot _native_InvoiceTotals_slots[] = {
        {Py_tp_free, (void *)_native::InvoiceTotals::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::InvoiceTotals> opaque(mod, "InvoiceTotals", nb::type_slots(_native_InvoiceTotals_slots));
    opaque
        .def("allowance_total", std::move(maybe_op_unwrap(&_native::InvoiceTotals::allowance_total)))
        .def("charge_total", std::move(maybe_op_unwrap(&_native::InvoiceTotals::charge_total)))
        .def("line_extension", std::move(maybe_op_unwrap(&_native::InvoiceTotals::line_extension)))
        .def("payable_amount", std::move(maybe_op_unwrap(&_native::InvoiceTotals::payable_amount)))
        .def("payable_rounding_amount", std::move(maybe_op_unwrap(&_native::InvoiceTotals::payable_rounding_amount)))
        .def("prepaid_amount", std::move(maybe_op_unwrap(&_native::InvoiceTotals::prepaid_amount)))
        .def("tax_amount", std::move(maybe_op_unwrap(&_native::InvoiceTotals::tax_amount)))
        .def("tax_inclusive", std::move(maybe_op_unwrap(&_native::InvoiceTotals::tax_inclusive)))
        .def("taxable_amount", std::move(maybe_op_unwrap(&_native::InvoiceTotals::taxable_amount)));
}

} 