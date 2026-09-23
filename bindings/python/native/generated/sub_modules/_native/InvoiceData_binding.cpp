#include "diplomat_nanobind_common.hpp"


#include "InvoiceData.hpp"

namespace _native {
void add_InvoiceData_binding(nb::module_ mod) {
    PyType_Slot _native_InvoiceData_slots[] = {
        {Py_tp_free, (void *)_native::InvoiceData::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::InvoiceData> opaque(mod, "InvoiceData", nb::type_slots(_native_InvoiceData_slots));
    opaque
        .def("allowance_reason", std::move(maybe_op_unwrap(&_native::InvoiceData::allowance_reason)))
        .def("buyer", std::move(maybe_op_unwrap(&_native::InvoiceData::buyer)))
        .def("currency", std::move(maybe_op_unwrap(&_native::InvoiceData::currency)))
        .def("flags_raw", &_native::InvoiceData::flags_raw)
        .def("id", std::move(maybe_op_unwrap(&_native::InvoiceData::id)))
        .def("invoice_counter", &_native::InvoiceData::invoice_counter)
        .def("invoice_level_charge", std::move(maybe_op_unwrap(&_native::InvoiceData::invoice_level_charge)))
        .def("invoice_level_discount", std::move(maybe_op_unwrap(&_native::InvoiceData::invoice_level_discount)))
        .def("invoice_sub_type", &_native::InvoiceData::invoice_sub_type)
        .def("invoice_type_kind", &_native::InvoiceData::invoice_type_kind)
        .def("issue_datetime", std::move(maybe_op_unwrap(&_native::InvoiceData::issue_datetime)))
        .def("line_item", std::move(maybe_op_unwrap(&_native::InvoiceData::line_item)), "index"_a)
        .def("line_items_len", &_native::InvoiceData::line_items_len)
        .def("note", std::move(maybe_op_unwrap(&_native::InvoiceData::note)))
        .def("original_invoice_reason", std::move(maybe_op_unwrap(&_native::InvoiceData::original_invoice_reason)))
        .def("original_invoice_ref", std::move(maybe_op_unwrap(&_native::InvoiceData::original_invoice_ref)))
        .def("payment_means_code", std::move(maybe_op_unwrap(&_native::InvoiceData::payment_means_code)))
        .def("previous_invoice_hash", std::move(maybe_op_unwrap(&_native::InvoiceData::previous_invoice_hash)))
        .def("seller", std::move(maybe_op_unwrap(&_native::InvoiceData::seller)))
        .def("uuid", std::move(maybe_op_unwrap(&_native::InvoiceData::uuid)))
        .def("vat_category", &_native::InvoiceData::vat_category);
}

} 