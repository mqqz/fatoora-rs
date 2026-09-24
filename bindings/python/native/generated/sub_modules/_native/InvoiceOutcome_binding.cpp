#include "diplomat_nanobind_common.hpp"


#include "InvoiceOutcome.hpp"

namespace _native {
void add_InvoiceOutcome_binding(nb::module_ mod) {
    nb::class_<_native::InvoiceOutcome> e_class(mod, "InvoiceOutcome");
    
        nb::enum_<_native::InvoiceOutcome::Value> enumerator(e_class, "InvoiceOutcome");
        enumerator
            .value("Unknown", _native::InvoiceOutcome::Unknown)
            .value("Accepted", _native::InvoiceOutcome::Accepted)
            .value("Rejected", _native::InvoiceOutcome::Rejected)
            .export_values();
    
        e_class
            .def(nb::init_implicit<_native::InvoiceOutcome::Value>())
            .def(nb::self == _native::InvoiceOutcome::Value())
            .def("__repr__", [](const _native::InvoiceOutcome& self){
                return nb::str(nb::cast(_native::InvoiceOutcome::Value(self)));
            });
}

} 