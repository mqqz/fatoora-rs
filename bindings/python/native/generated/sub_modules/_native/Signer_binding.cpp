#include "diplomat_nanobind_common.hpp"


#include "FinalizedInvoice.hpp"
#include "Signer.hpp"

namespace _native {
void add_Signer_binding(nb::module_ mod) {
    PyType_Slot _native_Signer_slots[] = {
        {Py_tp_free, (void *)_native::Signer::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::Signer> opaque(mod, "Signer", nb::type_slots(_native_Signer_slots));
    opaque
        .def("certificate_der", std::move(maybe_op_unwrap(&_native::Signer::certificate_der)))
        .def("certificate_pem", std::move(maybe_op_unwrap(&_native::Signer::certificate_pem)))
        .def_static("from_der", std::move(maybe_op_unwrap(&_native::Signer::from_der)), "cert_der"_a, "key_der"_a)
        .def_static("from_pem", std::move(maybe_op_unwrap(&_native::Signer::from_pem)), "cert_pem"_a, "key_pem"_a)
        .def("sign", std::move(maybe_op_unwrap(&_native::Signer::sign)), "invoice"_a)
        .def("sign_xml", std::move(maybe_op_unwrap(&_native::Signer::sign_xml)), "xml"_a);
}

} 