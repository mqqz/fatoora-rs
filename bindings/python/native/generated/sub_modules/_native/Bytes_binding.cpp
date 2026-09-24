#include "diplomat_nanobind_common.hpp"


#include "Bytes.hpp"

namespace _native {
void add_Bytes_binding(nb::module_ mod) {
    PyType_Slot _native_Bytes_slots[] = {
        {Py_tp_free, (void *)_native::Bytes::operator delete },
        {Py_tp_dealloc, (void *)diplomat_tp_dealloc},
        {0, nullptr}};
    
    nb::class_<_native::Bytes> opaque(mod, "Bytes", nb::type_slots(_native_Bytes_slots));
    opaque
        .def("as_slice", &_native::Bytes::as_slice, "The view is valid while this immutable owner remains alive.");
    
    // Copy byte outputs directly into Python bytes without a NumPy dependency.
    opaque.def("_copy", [](const _native::Bytes& value) {
        auto view = value.as_slice();
        return nb::bytes(view.data(), view.size());
    });
    
}

} 