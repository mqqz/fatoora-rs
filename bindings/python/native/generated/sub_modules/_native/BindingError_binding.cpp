#include "diplomat_nanobind_common.hpp"


#include "BindingError.hpp"

namespace _native {
void add_BindingError_binding(nb::module_ mod) {
    PyType_Slot _native_BindingError_slots[] = {
        {Py_tp_free, (void *)_native::BindingError::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::BindingError> opaque(mod, "BindingError", nb::type_slots(_native_BindingError_slots));
    opaque
        .def("code", &_native::BindingError::code)
        .def("details_json", &_native::BindingError::details_json)
        .def("message", &_native::BindingError::message);
}

} 