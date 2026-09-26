#![no_main]

use fatoora_core::invoice::xml::parse::{parse_finalized_invoice_xml, parse_signed_invoice_xml};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(invoice) = parse_finalized_invoice_xml(xml) {
        let exported = invoice.to_xml().expect("accepted model must serialize");
        let reparsed = parse_finalized_invoice_xml(&exported).expect("exported model must parse");
        assert_eq!(invoice.totals(), reparsed.totals());
    }
    if let Ok(invoice) = parse_signed_invoice_xml(xml) {
        // Imported signed bytes must remain intact; reformatting breaks signatures.
        assert_eq!(invoice.xml(), xml);
    }
});
