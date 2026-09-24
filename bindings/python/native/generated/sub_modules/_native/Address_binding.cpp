#include "diplomat_nanobind_common.hpp"


#include "Address.hpp"

namespace _native {
void add_Address_binding(nb::module_ mod) {
    PyType_Slot _native_Address_slots[] = {
        {Py_tp_free, (void *)_native::Address::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::Address> opaque(mod, "Address", nb::type_slots(_native_Address_slots));
    opaque
        .def("additional_number", std::move(maybe_op_unwrap(&_native::Address::additional_number)))
        .def("additional_street", std::move(maybe_op_unwrap(&_native::Address::additional_street)))
        .def("building_number", std::move(maybe_op_unwrap(&_native::Address::building_number)))
        .def("city", std::move(maybe_op_unwrap(&_native::Address::city)))
        .def("country_code", std::move(maybe_op_unwrap(&_native::Address::country_code)))
        .def("district", std::move(maybe_op_unwrap(&_native::Address::district)))
        .def_static("new", std::move(maybe_op_unwrap(&_native::Address::new_)), "country_code"_a, "city"_a, "street"_a, "building_number"_a, "postal_code"_a, "additional_street"_a= nb::none(), "additional_number"_a= nb::none(), "district"_a= nb::none())
        .def("postal_code", std::move(maybe_op_unwrap(&_native::Address::postal_code)))
        .def("street", std::move(maybe_op_unwrap(&_native::Address::street)));
}

} 