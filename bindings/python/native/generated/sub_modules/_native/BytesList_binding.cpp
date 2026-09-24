#include "diplomat_nanobind_common.hpp"


#include "BytesList.hpp"

namespace _native {
void add_BytesList_binding(nb::module_ mod) {
    PyType_Slot _native_BytesList_slots[] = {
        {Py_tp_free, (void *)_native::BytesList::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::BytesList> opaque(mod, "BytesList", nb::type_slots(_native_BytesList_slots));
    opaque
        .def("get", std::move(maybe_op_unwrap(&_native::BytesList::get)), "index"_a)
        .def("is_empty", &_native::BytesList::is_empty)
        .def("len", &_native::BytesList::len);
}

} 