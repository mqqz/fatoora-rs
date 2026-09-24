#include "diplomat_nanobind_common.hpp"


#include "Party.hpp"

namespace _native {
void add_Party_binding(nb::module_ mod) {
    PyType_Slot _native_Party_slots[] = {
        {Py_tp_free, (void *)_native::Party::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::Party> opaque(mod, "Party", nb::type_slots(_native_Party_slots));
    opaque
        .def("address", std::move(maybe_op_unwrap(&_native::Party::address)))
        .def("name", std::move(maybe_op_unwrap(&_native::Party::name)))
        .def("other_id", std::move(maybe_op_unwrap(&_native::Party::other_id)))
        .def("vat_id", std::move(maybe_op_unwrap(&_native::Party::vat_id)));
}

} 