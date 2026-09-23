#include "diplomat_nanobind_common.hpp"


#include "ValidationMessage.hpp"

namespace _native {
void add_ValidationMessage_binding(nb::module_ mod) {
    PyType_Slot _native_ValidationMessage_slots[] = {
        {Py_tp_free, (void *)_native::ValidationMessage::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::ValidationMessage> opaque(mod, "ValidationMessage", nb::type_slots(_native_ValidationMessage_slots));
    opaque
        .def("category", std::move(maybe_op_unwrap(&_native::ValidationMessage::category)))
        .def("code", std::move(maybe_op_unwrap(&_native::ValidationMessage::code)))
        .def("message", std::move(maybe_op_unwrap(&_native::ValidationMessage::message)))
        .def("message_type", std::move(maybe_op_unwrap(&_native::ValidationMessage::message_type)))
        .def("status", std::move(maybe_op_unwrap(&_native::ValidationMessage::status)));
}

} 