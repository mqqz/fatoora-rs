#include "diplomat_nanobind_common.hpp"


#include "ValidationResults.hpp"

namespace _native {
void add_ValidationResults_binding(nb::module_ mod) {
    PyType_Slot _native_ValidationResults_slots[] = {
        {Py_tp_free, (void *)_native::ValidationResults::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::ValidationResults> opaque(mod, "ValidationResults", nb::type_slots(_native_ValidationResults_slots));
    opaque
        .def("error_len", &_native::ValidationResults::error_len)
        .def("error_message", std::move(maybe_op_unwrap(&_native::ValidationResults::error_message)), "index"_a)
        .def("info_len", &_native::ValidationResults::info_len)
        .def("info_message", std::move(maybe_op_unwrap(&_native::ValidationResults::info_message)), "index"_a)
        .def("status", std::move(maybe_op_unwrap(&_native::ValidationResults::status)))
        .def("warning_len", &_native::ValidationResults::warning_len)
        .def("warning_message", std::move(maybe_op_unwrap(&_native::ValidationResults::warning_message)), "index"_a);
}

} 