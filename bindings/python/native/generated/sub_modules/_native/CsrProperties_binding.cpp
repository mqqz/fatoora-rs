#include "diplomat_nanobind_common.hpp"


#include "CsrProperties.hpp"
#include "SigningKey.hpp"

namespace _native {
void add_CsrProperties_binding(nb::module_ mod) {
    PyType_Slot _native_CsrProperties_slots[] = {
        {Py_tp_free, (void *)_native::CsrProperties::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::CsrProperties> opaque(mod, "CsrProperties", nb::type_slots(_native_CsrProperties_slots));
    opaque
        .def("build", std::move(maybe_op_unwrap(&_native::CsrProperties::build)), "key"_a, "env"_a)
        .def_static("from_properties_str", std::move(maybe_op_unwrap(&_native::CsrProperties::from_properties_str)), "properties"_a)
        .def_static("new", std::move(maybe_op_unwrap(&_native::CsrProperties::new_)), "common_name"_a, "serial_number"_a, "organization_identifier"_a, "organization_unit_name"_a, "organization_name"_a, "country_name"_a, "invoice_type"_a, "location_address"_a, "industry_business_category"_a)
        .def_static("parse_csr_config_file", std::move(maybe_op_unwrap(&_native::CsrProperties::parse_csr_config_file)), "path"_a);
}

} 