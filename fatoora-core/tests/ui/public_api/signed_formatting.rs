use fatoora_core::invoice::{SignedInvoice, xml::XmlFormat};
fn reformat(invoice: &SignedInvoice) {
    invoice.to_xml_with_format(XmlFormat::Compact);
}
fn main() {}
