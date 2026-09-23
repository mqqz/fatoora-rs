#include "diplomat_nanobind_common.hpp"


#include "FinalizedInvoice.hpp"

namespace _native {
void add_FinalizedInvoice_binding(nb::module_ mod) {
    PyType_Slot _native_FinalizedInvoice_slots[] = {
        {Py_tp_free, (void *)_native::FinalizedInvoice::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::FinalizedInvoice> opaque(mod, "FinalizedInvoice", nb::type_slots(_native_FinalizedInvoice_slots));
    opaque
        .def("data", std::move(maybe_op_unwrap(&_native::FinalizedInvoice::data)))
        .def_static("from_file", std::move(maybe_op_unwrap(&_native::FinalizedInvoice::from_file)), "value"_a)
        .def_static("from_xml", std::move(maybe_op_unwrap(&_native::FinalizedInvoice::from_xml)), "value"_a)
        .def("hash_base64", std::move(maybe_op_unwrap(&_native::FinalizedInvoice::hash_base64)))
        .def("totals", std::move(maybe_op_unwrap(&_native::FinalizedInvoice::totals)))
        .def("xml", std::move(maybe_op_unwrap(&_native::FinalizedInvoice::xml)));
}

} 