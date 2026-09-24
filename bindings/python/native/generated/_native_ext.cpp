#include "diplomat_nanobind_common.hpp"
#include <../src/nb_internals.h>  // Required for shimming

// Forward declarations for binding add functions
namespace _native{
  
void add_CsidCompliance_binding(nb::module_);
void add_CsidProduction_binding(nb::module_);
void add_ValidationMessage_binding(nb::module_);
void add_ValidationResponse_binding(nb::module_);
void add_ValidationResults_binding(nb::module_);
void add_ZatcaClient_binding(nb::module_);
void add_BindingError_binding(nb::module_);
void add_Text_binding(nb::module_);
void add_Bytes_binding(nb::module_);
void add_BytesList_binding(nb::module_);
void add_Config_binding(nb::module_);
void add_Csr_binding(nb::module_);
void add_CsrProperties_binding(nb::module_);
void add_Signer_binding(nb::module_);
void add_SigningKey_binding(nb::module_);
void add_Address_binding(nb::module_);
void add_FinalizedInvoice_binding(nb::module_);
void add_InvoiceBuilder_binding(nb::module_);
void add_InvoiceData_binding(nb::module_);
void add_InvoiceLineItem_binding(nb::module_);
void add_InvoiceNote_binding(nb::module_);
void add_InvoiceTotals_binding(nb::module_);
void add_OriginalInvoiceRef_binding(nb::module_);
void add_OtherId_binding(nb::module_);
void add_Party_binding(nb::module_);
void add_SignedInvoice_binding(nb::module_);
void add_VatId_binding(nb::module_);
void add_Xml_binding(nb::module_);
void add_InvoiceOutcome_binding(nb::module_);
}

// Nanobind does not usually support custom deleters, so we're shimming some of the machinery to add that ability.
// On module init, the dummy type will have the normal nanobind inst_dealloc function in the tp_dealloc slot, so we
// pull it out, store it here, and then call it in the tp_dealloc function we are shimming in to all our types.
// Our custom tp_dealloc function will call the tp_free function instead of `delete`, allowing us effectively to override
// the delete operator.
// See https://nanobind.readthedocs.io/en/latest/lowlevel.html#customizing-type-creation and
// https://github.com/wjakob/nanobind/discussions/932
void (*nb_tp_dealloc)(void *) = nullptr;

void diplomat_tp_dealloc(PyObject *self)
{
    using namespace nb::detail;
    PyTypeObject *tp = Py_TYPE(self);
    const type_data *t = nb_type_data(tp);

    nb_inst *inst = (nb_inst *)self;
    void *p = inst_ptr(inst);
    if (inst->destruct)
    {
        inst->destruct = false;
        check(t->flags & (uint32_t)type_flags::is_destructible,
              "nanobind::detail::inst_dealloc(\"%s\"): attempted to call "
              "the destructor of a non-destructible type!",
              t->name);
        if (t->flags & (uint32_t)type_flags::has_destruct)
            t->destruct(p);
    }
    if (inst->cpp_delete)
    {
        inst->cpp_delete = false;
        auto tp_free = (freefunc)(PyType_GetSlot(tp, Py_tp_free));
        (*tp_free)(p);
    }
    (*nb_tp_dealloc)(self);
}

struct _Dummy {};

NB_MODULE(_native, mod)
{
    using namespace _native;

    {
        nb::class_<_Dummy> dummy(mod, "__dummy__");
        nb_tp_dealloc = (void (*)(void *))nb::type_get_slot(dummy, Py_tp_dealloc);
    }

    nb::class_<std::monostate>(mod, "monostate")
        .def("__repr__", [](const std::monostate &)
             { return ""; })
        .def("__str__", [](const std::monostate &)
             { return ""; });// Module declarations
    // Add bindings
    add_CsidCompliance_binding(mod);
    add_CsidProduction_binding(mod);
    add_ValidationMessage_binding(mod);
    add_ValidationResponse_binding(mod);
    add_ValidationResults_binding(mod);
    add_ZatcaClient_binding(mod);
    add_BindingError_binding(mod);
    add_Text_binding(mod);
    add_Bytes_binding(mod);
    add_BytesList_binding(mod);
    add_Config_binding(mod);
    add_Csr_binding(mod);
    add_CsrProperties_binding(mod);
    add_Signer_binding(mod);
    add_SigningKey_binding(mod);
    add_Address_binding(mod);
    add_FinalizedInvoice_binding(mod);
    add_InvoiceBuilder_binding(mod);
    add_InvoiceData_binding(mod);
    add_InvoiceLineItem_binding(mod);
    add_InvoiceNote_binding(mod);
    add_InvoiceTotals_binding(mod);
    add_OriginalInvoiceRef_binding(mod);
    add_OtherId_binding(mod);
    add_Party_binding(mod);
    add_SignedInvoice_binding(mod);
    add_VatId_binding(mod);
    add_Xml_binding(mod);
    add_InvoiceOutcome_binding(mod);
    
    
}