#include "diplomat_nanobind_common.hpp"


#include "Config.hpp"
#include "Xml.hpp"

namespace _native {
void add_Xml_binding(nb::module_ mod) {
    PyType_Slot _native_Xml_slots[] = {
        {Py_tp_free, (void *)_native::Xml::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::Xml> opaque(mod, "Xml", nb::type_slots(_native_Xml_slots));
    opaque
        .def_static("hash", std::move(maybe_op_unwrap(&_native::Xml::hash)), "xml"_a)
        .def_static("validate", std::move(maybe_op_unwrap(&_native::Xml::validate)), "config"_a, "xml"_a)
        .def_static("validate_zatca", std::move(maybe_op_unwrap(&_native::Xml::validate_zatca)), "config"_a, "xml"_a, "options_json"_a= nb::none(), "Produce an owned local ZATCA report as JSON. Inspect is_valid before acceptance.\nOptions default when absent; JSON inputs are limited to 4 KiB.");
}

} 