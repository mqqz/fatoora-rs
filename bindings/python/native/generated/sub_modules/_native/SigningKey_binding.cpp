#include "diplomat_nanobind_common.hpp"


#include "SigningKey.hpp"

namespace _native {
void add_SigningKey_binding(nb::module_ mod) {
    PyType_Slot _native_SigningKey_slots[] = {
        {Py_tp_free, (void *)_native::SigningKey::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::SigningKey> opaque(mod, "SigningKey", nb::type_slots(_native_SigningKey_slots));
    opaque
        .def_static("from_der", std::move(maybe_op_unwrap(&_native::SigningKey::from_der)), "der"_a)
        .def_static("from_pem", std::move(maybe_op_unwrap(&_native::SigningKey::from_pem)), "pem"_a)
        .def_static("generate", std::move(maybe_op_unwrap(&_native::SigningKey::generate)))
        .def("to_der", std::move(maybe_op_unwrap(&_native::SigningKey::to_der)))
        .def("to_pem", std::move(maybe_op_unwrap(&_native::SigningKey::to_pem)));
}

} 