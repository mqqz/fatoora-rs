use super::integrity_xml::{invoice_digest, properties_preimage};
use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const UBL: &str = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2";
const CAC: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";
const CBC: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";
const EXT: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk-parity/cases")
}

#[test]
fn frozen_sdk_canonical_preimages_and_all_signed_variants_match() {
    let mut canonical_count = 0;
    let mut properties_count = 0;
    for entry in fs::read_dir(corpus()).unwrap() {
        let directory = entry.unwrap().path();
        let canonical = directory.join("canonical.xml");
        if canonical.exists() {
            let input = fs::read_to_string(directory.join("input.xml")).unwrap();
            let bytes = fs::read(canonical).unwrap();
            let expected = Base64::encode_string(&Sha256::digest(&bytes));
            assert_eq!(
                invoice_digest(&input).unwrap(),
                expected,
                "{}",
                directory.display()
            );
            canonical_count += 1;
            let signed = directory.join("sdk-signed.xml");
            if signed.exists() {
                let xml = fs::read_to_string(signed).unwrap();
                assert_eq!(
                    invoice_digest(&xml).unwrap(),
                    expected,
                    "{} signed",
                    directory.display()
                );
                let properties =
                    fs::read_to_string(directory.join("signed-properties.xml")).unwrap();
                assert_eq!(
                    properties_preimage(&xml).unwrap(),
                    properties,
                    "{} properties",
                    directory.display()
                );
                properties_count += 1;
            }
        }
    }
    assert!(
        canonical_count >= 30,
        "fixture inventory unexpectedly shrank"
    );
    assert_eq!(properties_count, 15);
}

fn invoice(contents: &str) -> String {
    format!(
        "<Invoice xmlns='{UBL}' xmlns:c='{CAC}' xmlns:b='{CBC}' xmlns:e='{EXT}' xmlns:fake='urn:fake'>{contents}</Invoice>"
    )
}

#[test]
fn digest_exclusions_use_expanded_names_and_exact_qr_string_value() {
    let base = invoice("<b:ID>same</b:ID>");
    let expected = invoice_digest(&base).unwrap();
    for excluded in [
        "<e:UBLExtensions><fake:changed/></e:UBLExtensions>",
        "<c:Signature><fake:changed/></c:Signature>",
        "<c:AdditionalDocumentReference><b:ID>QR</b:ID><fake:changed/></c:AdditionalDocumentReference>",
        "<c:AdditionalDocumentReference><b:ID>Q<fake:part>R</fake:part></b:ID></c:AdditionalDocumentReference>",
    ] {
        assert_eq!(
            invoice_digest(&invoice(&format!("<b:ID>same</b:ID>{excluded}"))).unwrap(),
            expected
        );
    }
    for included in [
        "<fake:UBLExtensions/>",
        "<fake:Signature/>",
        "<fake:AdditionalDocumentReference><b:ID>QR</b:ID></fake:AdditionalDocumentReference>",
        "<c:AdditionalDocumentReference><fake:ID>QR</fake:ID></c:AdditionalDocumentReference>",
        "<c:AdditionalDocumentReference><b:ID> QR </b:ID></c:AdditionalDocumentReference>",
        "<c:AdditionalDocumentReference><b:ID>qr</b:ID></c:AdditionalDocumentReference>",
    ] {
        assert_ne!(
            invoice_digest(&invoice(&format!("<b:ID>same</b:ID>{included}"))).unwrap(),
            expected
        );
    }
    assert_eq!(
        invoice_digest(&invoice("<b:ID>same</b:ID><!--ignored--> ")).unwrap(),
        invoice_digest(&invoice("<b:ID>same</b:ID> ")).unwrap()
    );
    assert_ne!(
        invoice_digest(&invoice("<b:ID>same</b:ID> ")).unwrap(),
        expected
    );
}

fn signature(properties: &str) -> String {
    format!(
        "<root xmlns:s='{DS}' xmlns:x='{XADES}' xmlns:a='urn:attribute'><s:Signature><s:Object><x:QualifyingProperties>{properties}</x:QualifyingProperties></s:Object></s:Signature></root>"
    )
}

#[test]
fn properties_preserve_aliases_and_declare_inherited_prefixes_per_scope() {
    let input = signature(
        "<x:SignedProperties Id='p' xmlns:local='urn:local' a:flag='yes'>\n<x:SignedSignatureProperties><s:DigestValue> &gt;&amp;&lt; </s:DigestValue><s:DigestMethod Algorithm='a'/></x:SignedSignatureProperties>\n</x:SignedProperties>",
    );
    let expected = format!(
        "<x:SignedProperties xmlns:x=\"{XADES}\" xmlns:local=\"urn:local\" Id=\"p\" xmlns:a=\"urn:attribute\" a:flag=\"yes\">\n<x:SignedSignatureProperties><s:DigestValue xmlns:s=\"{DS}\"> &gt;&amp;&lt; </s:DigestValue><s:DigestMethod xmlns:s=\"{DS}\" Algorithm=\"a\"/></x:SignedSignatureProperties>\n</x:SignedProperties>"
    );
    assert_eq!(properties_preimage(&input).unwrap(), expected);
}

#[test]
fn properties_preserve_text_cdata_comments_attributes_and_default_namespace_changes() {
    let input = format!(
        "<root xmlns:s='{DS}'><s:Signature><s:Object><QualifyingProperties xmlns='{XADES}'><SignedProperties Id=\"a'&quot;&amp;&gt;\" xml:lang='ar'><plain xmlns=''/><s:Value xmlns:s='urn:other'>&#13;&#10;&#9;مرحبا</s:Value><![CDATA[<s:DigestMethod> &]]><!--a--><?keep value?></SignedProperties></QualifyingProperties></s:Object></s:Signature></root>"
    );
    let expected = format!(
        "<SignedProperties xmlns=\"{XADES}\" Id=\"a'&quot;&amp;&gt;\" xml:lang=\"ar\"><plain xmlns=\"\"></plain><s:Value xmlns:s=\"urn:other\">\r\n\tمرحبا</s:Value><![CDATA[<s:DigestMethod> &]]><!--a--><?keep value?></SignedProperties>"
    );
    assert_eq!(properties_preimage(&input).unwrap(), expected);
}

#[test]
fn properties_require_one_namespace_exact_signature_chain() {
    assert!(properties_preimage(&signature("<x:SignedProperties/><x:SignedProperties/>")).is_err());
    assert!(properties_preimage(&signature("<SignedProperties/>")).is_err());
    assert!(
        properties_preimage(&format!(
            "<root xmlns:x='{XADES}'><x:SignedProperties/></root>"
        ))
        .is_err()
    );
    assert!(
        properties_preimage(&signature("<x:SignedProperties/>").replace(DS, "urn:lookalike"))
            .is_err()
    );
    assert_eq!(
        properties_preimage(&signature("<x:SignedProperties/>")).unwrap(),
        format!("<x:SignedProperties xmlns:x=\"{XADES}\"/>")
    );
}

#[test]
fn integrity_preimages_reject_unsafe_or_malformed_xml_before_libxml() {
    for xml in [
        "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>",
        "<?xml version='1.0' encoding='ISO-8859-1'?><x/>",
        "<x><broken></x>",
        "<unbound:x/>",
        "<x a='1' a='2'/>",
        "<x>\0</x>",
    ] {
        assert!(invoice_digest(xml).is_err(), "{xml:?}");
        assert!(properties_preimage(xml).is_err(), "{xml:?}");
    }
}
