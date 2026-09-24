#include "diplomat_nanobind_common.hpp"


#include "Text.hpp"

namespace _native {
void add_Text_binding(nb::module_ mod) {
    PyType_Slot _native_Text_slots[] = {
        {Py_tp_free, (void *)_native::Text::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::Text> opaque(mod, "Text", nb::type_slots(_native_Text_slots));
    opaque
        .def("value", std::move(maybe_op_unwrap(&_native::Text::value)));
}

} 