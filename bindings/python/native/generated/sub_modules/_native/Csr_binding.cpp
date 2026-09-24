#include "diplomat_nanobind_common.hpp"


#include "Csr.hpp"

namespace _native {
void add_Csr_binding(nb::module_ mod) {
    PyType_Slot _native_Csr_slots[] = {
        {Py_tp_free, (void *)_native::Csr::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::Csr> opaque(mod, "Csr", nb::type_slots(_native_Csr_slots));
    opaque
        .def("extension_values_der", std::move(maybe_op_unwrap(&_native::Csr::extension_values_der)))
        .def_static("from_der", std::move(maybe_op_unwrap(&_native::Csr::from_der)), "der"_a)
        .def("subject_string", std::move(maybe_op_unwrap(&_native::Csr::subject_string)))
        .def("to_base64", std::move(maybe_op_unwrap(&_native::Csr::to_base64)))
        .def("to_der", std::move(maybe_op_unwrap(&_native::Csr::to_der)))
        .def("to_pem", std::move(maybe_op_unwrap(&_native::Csr::to_pem)))
        .def("to_pem_base64", std::move(maybe_op_unwrap(&_native::Csr::to_pem_base64)));
}

} 