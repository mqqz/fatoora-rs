//! Pinned KSA document/reference predicates; translated expressions retain LGPL-3.0.
use super::{
    FailureKind,
    identity::optional_length,
    structural::{has_transaction, indicator},
    xml::{CAC, Name, NodeId, XmlView, a, b, normalize_space},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum KsaCommonCheck {
    OrderReferenceLength,
    ContractReferenceLength,
    Uuid,
    QrReference,
    QrLength,
    InvoiceCounter,
    ContractReference,
    CounterDigits,
    DifferentVatNumbers,
    SellerVat,
    SellerScheme,
    PreviousHash,
    TaxCurrency,
    ChargeReasonCode,
    NationalBuyer,
    PreviousHashAttachment,
    SignatureInformation,
    SignatureReference,
    SignatureMethod,
    ActualDeliveryDate,
    BuyerName,
}

impl KsaCommonCheck {
    pub fn contexts(self, xml: &XmlView) -> Vec<NodeId> {
        use KsaCommonCheck::*;
        match self {
            ChargeReasonCode => {
                if xml.is_document_root(0) {
                    xml.all(CAC, "AllowanceCharge")
                } else {
                    Vec::new()
                }
            }
            NationalBuyer => xml
                .all_path(&[a("TaxTotal"), a("TaxSubtotal"), a("TaxCategory")])
                .into_iter()
                .filter(|&node| {
                    xml.path(node, &[b("TaxExemptionReasonCode")])
                        .iter()
                        .any(|&id| {
                            matches!(xml.node(id).text.as_str(), "VATEX-SA-EDU" | "VATEX-SA-HEA")
                        })
                })
                .collect(),
            PreviousHashAttachment
            | SignatureInformation
            | SignatureReference
            | SignatureMethod => xml.all_path(&[a("AdditionalDocumentReference"), a("Attachment")]),
            ActualDeliveryDate => xml.all_path(&[a("Delivery"), b("LatestDeliveryDate")]),
            BuyerName => xml.all_path(&[a("AccountingCustomerParty"), a("Party")]),
            _ => {
                if xml.is_document_root(0) {
                    vec![0]
                } else {
                    Vec::new()
                }
            }
        }
    }

    pub fn passes(self, xml: &XmlView, node: NodeId) -> Result<bool, FailureKind> {
        use KsaCommonCheck::*;
        match self {
            OrderReferenceLength | ContractReferenceLength => {
                let element = if matches!(self, OrderReferenceLength) {
                    "OrderReference"
                } else {
                    "ContractDocumentReference"
                };
                optional_length(xml, &xml.path(node, &[a(element), b("ID")]), 0, 127)
            }
            Uuid => {
                let ids = xml.path(node, &[b("UUID")]);
                if !nonempty(xml, &ids) {
                    return Ok(false);
                }
                // XML Schema \w excludes punctuation, separators and control/
                // unassigned characters. The source has no trailing anchor.
                static WORD: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
                    regex::Regex::new(r"^(?:[^\p{P}\p{Z}\p{C}]|[.-])").expect("constant regex")
                });
                Ok(WORD.is_match(text(xml, &ids)?))
            }
            QrReference => {
                if !has_transaction(xml, "02") {
                    return Ok(true);
                }
                let normalized = references(xml, node, "QR", true)?;
                if normalized.is_empty() || binaries(xml, &normalized).is_empty() {
                    return Ok(false);
                }
                let raw = references(xml, node, "QR", false)?;
                let binaries = binaries(xml, &raw);
                Ok(!normalize_space(text(xml, &binaries)?).is_empty()
                    && has_plain_mime(xml, &binaries))
            }
            QrLength => optional_length(
                xml,
                &binaries(xml, &references(xml, node, "QR", true)?),
                1,
                1000,
            ),
            InvoiceCounter => Ok(!references(xml, node, "ICV", true)?.is_empty()
                && nonempty(
                    xml,
                    &xml.path(node, &[a("AdditionalDocumentReference"), b("UUID")]),
                )),
            ContractReference => {
                let applies = xml.all_path(&[b("InvoiceTypeCode")]).iter().any(|&id| {
                    let name: Vec<_> = xml
                        .attribute(id, "", "name")
                        .unwrap_or("")
                        .chars()
                        .collect();
                    name.len() == 9
                        && name[0] == '0'
                        && matches!(name[1], '1' | '2')
                        && name[8] == '1'
                });
                Ok(!applies
                    || !normalize_space(text(
                        xml,
                        &xml.path(node, &[a("ContractDocumentReference"), b("ID")]),
                    )?)
                    .is_empty())
            }
            CounterDigits => Ok(text(
                xml,
                &xml.path(node, &[a("AdditionalDocumentReference"), b("UUID")]),
            )?
            .bytes()
            .all(|c| c.is_ascii_digit())),
            DifferentVatNumbers => {
                let supplier = xml.path(node, &vat_path("AccountingSupplierParty"));
                let buyer = xml.path(node, &vat_path("AccountingCustomerParty"));
                Ok(!(nonempty(xml, &supplier)
                    && nonempty(xml, &buyer)
                    && supplier.iter().any(|&seller| {
                        buyer
                            .iter()
                            .any(|&buyer| xml.node(seller).text == xml.node(buyer).text)
                    })))
            }
            SellerVat => {
                if !nonempty(xml, &xml.path(node, &vat_path("AccountingSupplierParty"))) {
                    return Ok(false);
                }
                for scheme in xml.path(
                    node,
                    &[
                        a("AccountingSupplierParty"),
                        a("Party"),
                        a("PartyTaxScheme"),
                        a("TaxScheme"),
                    ],
                ) {
                    if normalize_space(text(xml, &xml.path(scheme, &[b("ID")]))?) == "VAT" {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            SellerScheme => {
                let ids = xml.path(
                    node,
                    &[
                        a("AccountingSupplierParty"),
                        a("Party"),
                        a("PartyIdentification"),
                        b("ID"),
                    ],
                );
                let id = match ids.as_slice() {
                    [] => return Ok(false),
                    [id] => *id,
                    _ => return Err(FailureKind::Cardinality),
                };
                // ID/normalize-space(@schemeID) produces one string per ID,
                // even for an ID without the attribute.
                let scheme = normalize_space(xml.attribute(id, "", "schemeID").unwrap_or(""));
                Ok(scheme.chars().count() > 2 && "CRN MOM MLS SAG OTH 700".contains(&scheme))
            }
            PreviousHash => {
                let references = references(xml, node, "PIH", true)?;
                let binaries = binaries(xml, &references);
                Ok(!references.is_empty()
                    && nonempty(xml, &binaries)
                    && has_plain_mime(xml, &binaries))
            }
            TaxCurrency => Ok(nonempty(xml, &xml.path(node, &[b("TaxCurrencyCode")]))),
            ChargeReasonCode => {
                if xml
                    .node(node)
                    .parent
                    .is_some_and(|parent| xml.is(parent, CAC, "Price"))
                    || !indicator(xml, node, true)?
                {
                    return Ok(true);
                }
                // Source contains() uses the raw code without token padding.
                Ok(CHARGE_CODES.contains(text(
                    xml,
                    &xml.path(node, &[b("AllowanceChargeReasonCode")]),
                )?))
            }
            NationalBuyer => {
                let ids = xml.all_path(&[
                    a("AccountingCustomerParty"),
                    a("Party"),
                    a("PartyIdentification"),
                    b("ID"),
                ]);
                Ok(ids
                    .iter()
                    .any(|&id| xml.attribute(id, "", "schemeID") == Some("NAT")))
            }
            PreviousHashAttachment
            | SignatureInformation
            | SignatureReference
            | SignatureMethod => {
                let parent = xml
                    .node(node)
                    .parent
                    .expect("selected attachment has a parent");
                let is_pih = normalize_space(text(xml, &xml.path(parent, &[b("ID")]))?) == "PIH";
                if matches!(self, PreviousHashAttachment) {
                    let values = xml.path(node, &[b("EmbeddedDocumentBinaryObject")]);
                    return Ok(!is_pih || (nonempty(xml, &values) && has_plain_mime(xml, &values)));
                }
                // PIH template015 wins over template016 in the same pattern.
                if is_pih || !has_transaction(xml, "02") {
                    return Ok(true);
                }
                match self {
                    SignatureInformation => Ok(nonempty(
                        xml,
                        &xml.path(node, &[b("EmbeddedDocumentBinaryObject")]),
                    ) && equals(
                        xml,
                        &xml.all_path(&signature_information_path(b("ID"))),
                        "urn:oasis:names:specification:ubl:signature:1",
                    )),
                    SignatureReference => Ok(equals(
                        xml,
                        &xml.all_path(&[a("Signature"), b("ID")]),
                        INVOICE_SIGNATURE,
                    ) && normalize_space(text(
                        xml,
                        &xml.all_path(&signature_information_path((SBC, "ReferencedSignatureID"))),
                    )?) == INVOICE_SIGNATURE),
                    SignatureMethod => Ok(nonempty(
                        xml,
                        &xml.path(node, &[b("EmbeddedDocumentBinaryObject")]),
                    ) && equals(
                        xml,
                        &xml.all_path(&[a("Signature"), b("SignatureMethod")]),
                        "urn:oasis:names:specification:ubl:dsig:enveloped:xades",
                    )),
                    _ => unreachable!(),
                }
            }
            ActualDeliveryDate => {
                let parent = xml
                    .node(node)
                    .parent
                    .expect("selected delivery date has a parent");
                Ok(
                    !normalize_space(text(xml, &xml.path(parent, &[b("ActualDeliveryDate")]))?)
                        .is_empty(),
                )
            }
            BuyerName => Ok(!has_transaction(xml, "01")
                || nonempty(
                    xml,
                    &xml.path(node, &[a("PartyLegalEntity"), b("RegistrationName")]),
                )),
        }
    }
}

fn text<'a>(xml: &'a XmlView, ids: &[NodeId]) -> Result<&'a str, FailureKind> {
    Ok(xml.singleton_text(ids)?.unwrap_or(""))
}
fn nonempty(xml: &XmlView, ids: &[NodeId]) -> bool {
    ids.iter().any(|&id| !xml.node(id).text.is_empty())
}
fn equals(xml: &XmlView, ids: &[NodeId], expected: &str) -> bool {
    ids.iter().any(|&id| xml.node(id).text == expected)
}
fn vat_path(role: &'static str) -> [Name; 4] {
    [a(role), a("Party"), a("PartyTaxScheme"), b("CompanyID")]
}
fn references(
    xml: &XmlView,
    parent: NodeId,
    kind: &str,
    normalized: bool,
) -> Result<Vec<NodeId>, FailureKind> {
    let mut result = Vec::new();
    for id in xml.path(parent, &[a("AdditionalDocumentReference")]) {
        let ids = xml.path(id, &[b("ID")]);
        let matches = if normalized {
            normalize_space(text(xml, &ids)?) == kind
        } else {
            equals(xml, &ids, kind)
        };
        if matches {
            result.push(id);
        }
    }
    Ok(result)
}
fn binaries(xml: &XmlView, references: &[NodeId]) -> Vec<NodeId> {
    references
        .iter()
        .flat_map(|&id| xml.path(id, &[a("Attachment"), b("EmbeddedDocumentBinaryObject")]))
        .collect()
}
fn has_plain_mime(xml: &XmlView, binaries: &[NodeId]) -> bool {
    binaries
        .iter()
        .any(|&id| normalize_space(xml.attribute(id, "", "mimeCode").unwrap_or("")) == "text/plain")
}
const EXT: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";
const SIG: &str = "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2";
const SAC: &str = "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2";
const SBC: &str = "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2";
const INVOICE_SIGNATURE: &str = "urn:oasis:names:specification:ubl:signature:Invoice";
fn signature_information_path(last: Name) -> [Name; 6] {
    [
        (EXT, "UBLExtensions"),
        (EXT, "UBLExtension"),
        (EXT, "ExtensionContent"),
        (SIG, "UBLDocumentSignatures"),
        (SAC, "SignatureInformation"),
        last,
    ]
}
const CHARGE_CODES: &str = " AA AAA AAC AAD AAE AAF AAH AAI AAS AAT AAV AAY AAZ ABA ABB ABC ABD ABF ABK ABL ABN ABR ABS ABT ABU ACF ACG ACH ACI ACJ ACK ACL ACM ACS ADC ADE ADJ ADK ADL ADM ADN ADO ADP ADQ ADR ADT ADW ADY ADZ AEA AEB AEC AED AEF AEH AEI AEJ AEK AEL AEM AEN AEO AEP AES AET AEU AEV AEW AEX AEY AEZ AJ AU CA CAB CAD CAE CAF CAI CAJ CAK CAL CAM CAN CAO CAPCAQ CAR CAS CAT CAU CAV CAW CD CG CS CT DAB DAD DL EG EP ER FAA FAB FAC FC FH FI GAA HAA HD HH IAA AB ID IF IR IS KO L1 LA LAA LAB LF MAE MI ML NAA OA PA PAA PC PL RAB RAC RAD RAF RE RF RH RV SA SAA SAD SAE SAI SG SH SM SU TAB AC TT TV V1 V2 WH XAA YY ZZZ ";
