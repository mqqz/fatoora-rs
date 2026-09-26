#![no_main]

use base64ct::{Base64, Encoding};
use fatoora_core::invoice::xml::parse::parse_signed_invoice_xml;
use libfuzzer_sys::fuzz_target;

const INVOICE: &str = include_str!("../seeds/xml_parse/signed.xml");

fuzz_target!(|data: &[u8]| {
    let Some((&mode, payload)) = data.split_first() else {
        return;
    };
    // Raw TLV mode reaches the decoder without a base64 mutation barrier.
    // Text mode also exercises malformed base64 through the public importer.
    let encoded = if mode % 2 == 0 {
        Base64::encode_string(payload)
    } else {
        let Ok(text) = std::str::from_utf8(payload) else {
            return;
        };
        // Keep XML valid so arbitrary input reaches QR decoding.
        if text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
        {
            return;
        }
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let qr_start = INVOICE.find("<cbc:ID>QR</cbc:ID>").unwrap();
    let tag_start = qr_start
        + INVOICE[qr_start..]
            .find("<cbc:EmbeddedDocumentBinaryObject")
            .unwrap();
    let start = tag_start + INVOICE[tag_start..].find('>').unwrap() + 1;
    let end = start
        + INVOICE[start..]
            .find("</cbc:EmbeddedDocumentBinaryObject>")
            .unwrap();
    let xml = format!("{}{}{}", &INVOICE[..start], encoded, &INVOICE[end..]);
    if let Ok(invoice) = parse_signed_invoice_xml(&xml) {
        assert_eq!(invoice.xml(), xml);
        // A valid stream followed by one tag byte is a truncated header.
        // The decoder must reject it rather than silently accept a prefix.
        let mut truncated = if mode % 2 == 0 {
            payload.to_vec()
        } else {
            Base64::decode_vec(std::str::from_utf8(payload).unwrap().trim()).unwrap()
        };
        truncated.push(6);
        let malformed = format!(
            "{}{}{}",
            &INVOICE[..start],
            Base64::encode_string(&truncated),
            &INVOICE[end..]
        );
        assert!(parse_signed_invoice_xml(&malformed).is_err());
    }
});
