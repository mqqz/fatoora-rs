// Copy byte outputs directly into Python bytes without a NumPy dependency.
opaque.def("_copy", [](const _native::Bytes& value) {
    auto view = value.as_slice();
    return nb::bytes(view.data(), view.size());
});
