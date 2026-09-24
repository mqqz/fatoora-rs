// Blocking operations release the GIL; the Python facade locks all input owners.
opaque.def("_blocking_post_csr_for_ccsid", maybe_op_unwrap(&_native::ZatcaClient::post_csr_for_ccsid), nb::call_guard<nb::gil_scoped_release>());
opaque.def("_blocking_post_ccsid_for_pcsid", maybe_op_unwrap(&_native::ZatcaClient::post_ccsid_for_pcsid), nb::call_guard<nb::gil_scoped_release>());
opaque.def("_blocking_renew_csid", maybe_op_unwrap(&_native::ZatcaClient::renew_csid), nb::call_guard<nb::gil_scoped_release>());
opaque.def("_blocking_check_invoice_compliance", maybe_op_unwrap(&_native::ZatcaClient::check_invoice_compliance), nb::call_guard<nb::gil_scoped_release>());
opaque.def("_blocking_report_simplified_invoice", maybe_op_unwrap(&_native::ZatcaClient::report_simplified_invoice), nb::call_guard<nb::gil_scoped_release>());
opaque.def("_blocking_clear_standard_invoice", maybe_op_unwrap(&_native::ZatcaClient::clear_standard_invoice), nb::call_guard<nb::gil_scoped_release>());
