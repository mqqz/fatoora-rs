#include "diplomat_nanobind_common.hpp"


#include "CsidCompliance.hpp"

namespace _native {
void add_CsidCompliance_binding(nb::module_ mod) {
    PyType_Slot _native_CsidCompliance_slots[] = {
        {Py_tp_free, (void *)_native::CsidCompliance::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::CsidCompliance> opaque(mod, "CsidCompliance", nb::type_slots(_native_CsidCompliance_slots));
    opaque
        .def("binary_security_token", std::move(maybe_op_unwrap(&_native::CsidCompliance::binary_security_token)))
        .def_static("create", std::move(maybe_op_unwrap(&_native::CsidCompliance::create)), "environment"_a, "request_id"_a= nb::none(), "token"_a, "secret"_a)
        .def("env", &_native::CsidCompliance::env)
        .def("request_id", std::move(maybe_op_unwrap(&_native::CsidCompliance::request_id)))
        .def("secret", std::move(maybe_op_unwrap(&_native::CsidCompliance::secret)));
}

} 