#include "diplomat_nanobind_common.hpp"


#include "VatId.hpp"

namespace _native {
void add_VatId_binding(nb::module_ mod) {
    PyType_Slot _native_VatId_slots[] = {
        {Py_tp_free, (void *)_native::VatId::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::VatId> opaque(mod, "VatId", nb::type_slots(_native_VatId_slots));
    opaque
        .def("value", std::move(maybe_op_unwrap(&_native::VatId::value)));
}

} 