#include "diplomat_nanobind_common.hpp"


#include "Config.hpp"

namespace _native {
void add_Config_binding(nb::module_ mod) {
    PyType_Slot _native_Config_slots[] = {
        {Py_tp_free, (void *)_native::Config::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::Config> opaque(mod, "Config", nb::type_slots(_native_Config_slots));
    opaque
        .def("env", &_native::Config::env)
        .def_static("new", std::move(maybe_op_unwrap(&_native::Config::new_)), "env"_a);
}

} 