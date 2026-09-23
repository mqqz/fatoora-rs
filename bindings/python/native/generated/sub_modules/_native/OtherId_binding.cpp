#include "diplomat_nanobind_common.hpp"


#include "OtherId.hpp"

namespace _native {
void add_OtherId_binding(nb::module_ mod) {
    PyType_Slot _native_OtherId_slots[] = {
        {Py_tp_free, (void *)_native::OtherId::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::OtherId> opaque(mod, "OtherId", nb::type_slots(_native_OtherId_slots));
    opaque
        .def("scheme", std::move(maybe_op_unwrap(&_native::OtherId::scheme)))
        .def("value", std::move(maybe_op_unwrap(&_native::OtherId::value)));
}

} 