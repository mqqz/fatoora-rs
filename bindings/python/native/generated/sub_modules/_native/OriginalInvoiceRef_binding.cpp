#include "diplomat_nanobind_common.hpp"


#include "OriginalInvoiceRef.hpp"

namespace _native {
void add_OriginalInvoiceRef_binding(nb::module_ mod) {
    PyType_Slot _native_OriginalInvoiceRef_slots[] = {
        {Py_tp_free, (void *)_native::OriginalInvoiceRef::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::OriginalInvoiceRef> opaque(mod, "OriginalInvoiceRef", nb::type_slots(_native_OriginalInvoiceRef_slots));
    opaque
        .def("id", std::move(maybe_op_unwrap(&_native::OriginalInvoiceRef::id)))
        .def("issue_date", std::move(maybe_op_unwrap(&_native::OriginalInvoiceRef::issue_date)))
        .def("uuid", std::move(maybe_op_unwrap(&_native::OriginalInvoiceRef::uuid)));
}

} 