#include "diplomat_nanobind_common.hpp"


#include "SignedInvoice.hpp"

namespace _native {
void add_SignedInvoice_binding(nb::module_ mod) {
    PyType_Slot _native_SignedInvoice_slots[] = {
        {Py_tp_free, (void *)_native::SignedInvoice::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::SignedInvoice> opaque(mod, "SignedInvoice", nb::type_slots(_native_SignedInvoice_slots));
    opaque
        .def("cert_hash", std::move(maybe_op_unwrap(&_native::SignedInvoice::cert_hash)))
        .def("data", std::move(maybe_op_unwrap(&_native::SignedInvoice::data)))
        .def_static("from_file", std::move(maybe_op_unwrap(&_native::SignedInvoice::from_file)), "value"_a)
        .def_static("from_xml", std::move(maybe_op_unwrap(&_native::SignedInvoice::from_xml)), "value"_a)
        .def("hash_base64", std::move(maybe_op_unwrap(&_native::SignedInvoice::hash_base64)))
        .def("into_xml", std::move(maybe_op_unwrap(&_native::SignedInvoice::into_xml)))
        .def("invoice_hash", std::move(maybe_op_unwrap(&_native::SignedInvoice::invoice_hash)))
        .def("issuer", std::move(maybe_op_unwrap(&_native::SignedInvoice::issuer)))
        .def("public_key", std::move(maybe_op_unwrap(&_native::SignedInvoice::public_key)))
        .def("qr_code", std::move(maybe_op_unwrap(&_native::SignedInvoice::qr_code)))
        .def("serial", std::move(maybe_op_unwrap(&_native::SignedInvoice::serial)))
        .def("signature", std::move(maybe_op_unwrap(&_native::SignedInvoice::signature)))
        .def("signed_props_hash", std::move(maybe_op_unwrap(&_native::SignedInvoice::signed_props_hash)))
        .def("signing_time", std::move(maybe_op_unwrap(&_native::SignedInvoice::signing_time)))
        .def("to_xml_base64", std::move(maybe_op_unwrap(&_native::SignedInvoice::to_xml_base64)))
        .def("totals", std::move(maybe_op_unwrap(&_native::SignedInvoice::totals)))
        .def("xml", std::move(maybe_op_unwrap(&_native::SignedInvoice::xml)))
        .def("zatca_key_signature", std::move(maybe_op_unwrap(&_native::SignedInvoice::zatca_key_signature)));
}

} 