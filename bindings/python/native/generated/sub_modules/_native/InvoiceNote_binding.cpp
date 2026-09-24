#include "diplomat_nanobind_common.hpp"


#include "InvoiceNote.hpp"

namespace _native {
void add_InvoiceNote_binding(nb::module_ mod) {
    PyType_Slot _native_InvoiceNote_slots[] = {
        {Py_tp_free, (void *)_native::InvoiceNote::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::InvoiceNote> opaque(mod, "InvoiceNote", nb::type_slots(_native_InvoiceNote_slots));
    opaque
        .def("language", std::move(maybe_op_unwrap(&_native::InvoiceNote::language)))
        .def("text", std::move(maybe_op_unwrap(&_native::InvoiceNote::text)));
}

} 