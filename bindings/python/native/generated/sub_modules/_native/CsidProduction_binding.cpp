#include "diplomat_nanobind_common.hpp"


#include "CsidProduction.hpp"

namespace _native {
void add_CsidProduction_binding(nb::module_ mod) {
    PyType_Slot _native_CsidProduction_slots[] = {
        {Py_tp_free, (void *)_native::CsidProduction::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::CsidProduction> opaque(mod, "CsidProduction", nb::type_slots(_native_CsidProduction_slots));
    opaque
        .def("binary_security_token", std::move(maybe_op_unwrap(&_native::CsidProduction::binary_security_token)))
        .def_static("create", std::move(maybe_op_unwrap(&_native::CsidProduction::create)), "environment"_a, "request_id"_a= nb::none(), "token"_a, "secret"_a)
        .def("env", &_native::CsidProduction::env)
        .def("request_id", std::move(maybe_op_unwrap(&_native::CsidProduction::request_id)))
        .def("secret", std::move(maybe_op_unwrap(&_native::CsidProduction::secret)));
}

} 