pub(crate) const INVOICE_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2";
pub(crate) const CBC_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";
pub(crate) const CAC_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";
pub(crate) const EXT_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";
pub(crate) const SIG_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2";
pub(crate) const SAC_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2";
pub(crate) const SBC_NS: &str =
    "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2";
pub(crate) const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub(crate) const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";

pub(crate) const UBL_EXTENSIONS_TEMPLATE: &str =
    include_str!("../../../assets/templates/ubl_extensions.xml");
pub(crate) const CAC_SIGNATURE_TEMPLATE: &str =
    include_str!("../../../assets/templates/cac_signature.xml");
pub(crate) const QR_REFERENCE_TEMPLATE: &str =
    include_str!("../../../assets/templates/qr_reference.xml");
