use fatoora_core::invoice::FinalizedInvoice;
fn reformat(invoice: &FinalizedInvoice) {
    invoice.to_xml_pretty();
}
fn main() {}
