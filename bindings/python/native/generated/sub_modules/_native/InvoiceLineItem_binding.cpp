#include "diplomat_nanobind_common.hpp"


#include "InvoiceLineItem.hpp"

namespace _native {
void add_InvoiceLineItem_binding(nb::module_ mod) {
    PyType_Slot _native_InvoiceLineItem_slots[] = {
        {Py_tp_free, (void *)_native::InvoiceLineItem::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::InvoiceLineItem> opaque(mod, "InvoiceLineItem", nb::type_slots(_native_InvoiceLineItem_slots));
    opaque
        .def("description", std::move(maybe_op_unwrap(&_native::InvoiceLineItem::description)))
        .def("quantity", std::move(maybe_op_unwrap(&_native::InvoiceLineItem::quantity)))
        .def("total_amount", std::move(maybe_op_unwrap(&_native::InvoiceLineItem::total_amount)))
        .def("unit_code", std::move(maybe_op_unwrap(&_native::InvoiceLineItem::unit_code)))
        .def("unit_price", std::move(maybe_op_unwrap(&_native::InvoiceLineItem::unit_price)))
        .def("vat_amount", std::move(maybe_op_unwrap(&_native::InvoiceLineItem::vat_amount)))
        .def("vat_category", &_native::InvoiceLineItem::vat_category)
        .def("vat_rate", std::move(maybe_op_unwrap(&_native::InvoiceLineItem::vat_rate)));
}

} 