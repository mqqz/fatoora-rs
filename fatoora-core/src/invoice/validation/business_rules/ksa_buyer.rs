//! Buyer and transaction predicates translated from the pinned KSA profile.
//! Executable guards, including global XPath scopes, retain LGPL-3.0 terms.
use super::{
    FailureKind,
    structural::has_transaction,
    xml::{CAC, CBC, Name, NodeId, UBL, XmlView, a, b, normalize_space},
};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy)]
pub(super) enum KsaBuyerCheck {
    SaAddress,
    DistrictRequired,
    DistrictLength,
    SellerDistrict,
    Postcode,
    SummaryDates,
    LineTax,
    StreetRequired,
    CityRequired,
    SimpleNameLength,
    StandardNameLength,
    LineInclusive,
    PaymentNoteLength,
    SimpleStreetLength,
    CityLength,
    PaymentCode,
    BuyerAddress,
    AccountLength,
    SupplyDate,
    NoteReason,
    MissingPayment,
    NoteReasonLength,
    NoteReference,
    NoteReferenceLength,
    MissingReference,
    SimpleBuyer,
    SimpleFlags,
    Stamp,
    SummaryBuyer,
    ExportSelfBilling,
    EmptyBuyerVat,
}

impl KsaBuyerCheck {
    pub fn contexts(self, xml: &XmlView) -> Vec<NodeId> {
        use KsaBuyerCheck::*;
        match self {
            SaAddress | DistrictRequired | DistrictLength | SellerDistrict | Postcode
            | SummaryDates => xml
                .all_path(&[
                    a("AccountingCustomerParty"),
                    a("Party"),
                    a("PostalAddress"),
                    a("Country"),
                ])
                .into_iter()
                .filter(|&n| {
                    xml.path(n, &[b("IdentificationCode")])
                        .iter()
                        .any(|&id| xml.node(id).text == "SA")
                })
                .collect(),
            NoteReason | MissingPayment | NoteReasonLength | NoteReference
            | NoteReferenceLength | MissingReference => {
                if !xml.is(0, UBL, "Invoice")
                    || !xml
                        .path(0, &[b("InvoiceTypeCode")])
                        .iter()
                        .any(|&n| ["381", "383"].contains(&xml.node(n).text.as_str()))
                {
                    return Vec::new();
                }
                match self {
                    NoteReason => xml.all(CAC, "PaymentMeans"),
                    MissingPayment => {
                        if xml.all(CAC, "PaymentMeans").is_empty() {
                            vec![0]
                        } else {
                            vec![]
                        }
                    }
                    NoteReasonLength => xml.all_path(&[a("PaymentMeans"), b("InstructionNote")]),
                    NoteReference | NoteReferenceLength => xml.all(CAC, "BillingReference"),
                    MissingReference => {
                        if xml.all(CAC, "BillingReference").is_empty() {
                            vec![0]
                        } else {
                            vec![]
                        }
                    }
                    _ => unreachable!(),
                }
            }
            EmptyBuyerVat => xml.all_path(&[
                a("AccountingCustomerParty"),
                a("Party"),
                a("PartyTaxScheme"),
                b("CompanyID"),
            ]),
            _ => {
                let types = xml
                    .all(CBC, "InvoiceTypeCode")
                    .into_iter()
                    .filter(|&n| {
                        let name = xml.attribute(n, "", "name").unwrap_or("");
                        match self {
                            SupplyDate => {
                                name.starts_with("01")
                                    && xml.is(0, UBL, "Invoice")
                                    && xml
                                        .path(0, &[b("InvoiceTypeCode")])
                                        .iter()
                                        .any(|&t| xml.node(t).text == "388")
                            }
                            SimpleBuyer | SimpleFlags | Stamp | SummaryBuyer => {
                                name.starts_with("02")
                            }
                            ExportSelfBilling => name.chars().nth(4) == Some('1'),
                            _ => name.starts_with("01") || name.starts_with("02"),
                        }
                    })
                    .collect::<Vec<_>>();
                if matches!(self, PaymentCode) {
                    // A global for-each executes once for every selected type.
                    types
                        .iter()
                        .flat_map(|_| xml.all_path(&[a("PaymentMeans"), b("PaymentMeansCode")]))
                        .collect()
                } else {
                    types
                }
            }
        }
    }

    pub fn passes(self, xml: &XmlView, node: NodeId) -> Result<bool, FailureKind> {
        use KsaBuyerCheck::*;
        let standard = || has_transaction(xml, "01");
        let simple = || {
            xml.all(CBC, "InvoiceTypeCode")
                .iter()
                .any(|&n| transaction(xml.attribute(n, "", "name").unwrap_or(""), false))
        };
        let address = |field| buyer_path(&[a("PostalAddress"), b(field)]);
        let name = buyer_path(&[a("PartyLegalEntity"), b("RegistrationName")]);
        Ok(match self {
            SaAddress => {
                if !standard() {
                    return Ok(true);
                }
                for field in [
                    "StreetName",
                    "BuildingNumber",
                    "PostalZone",
                    "CityName",
                    "CitySubdivisionName",
                ] {
                    if !nonempty_normalized(xml, &xml.all_path(&address(field)))? {
                        return Ok(false);
                    }
                }
                nonempty_normalized(
                    xml,
                    &xml.all_path(&buyer_path(&[
                        a("PostalAddress"),
                        a("Country"),
                        b("IdentificationCode"),
                    ])),
                )?
            }
            DistrictRequired => {
                !standard() || length(xml, &address("CitySubdivisionName"), 1, usize::MAX, true)?
            }
            DistrictLength => {
                !standard() || length(xml, &address("CitySubdivisionName"), 0, 127, false)?
            }
            SellerDistrict => length(
                xml,
                &[
                    a("AccountingSupplierParty"),
                    a("Party"),
                    a("PostalAddress"),
                    b("CitySubdivisionName"),
                ],
                1,
                127,
                false,
            )?,
            Postcode => {
                if !standard() {
                    return Ok(true);
                }
                let nodes = xml.all_path(&address("PostalZone"));
                let value = xml.singleton_text(&nodes)?.unwrap_or("");
                value.len() == 5 && value.bytes().all(|c| c.is_ascii_digit())
            }
            SummaryDates => {
                !has_summary(xml)
                    || (!xml.all(CBC, "ActualDeliveryDate").is_empty()
                        && !xml.all(CBC, "LatestDeliveryDate").is_empty())
            }
            LineTax | LineInclusive => {
                !standard()
                    || xml.all(CAC, "InvoiceLine").iter().all(|&line| {
                        any_nonempty(
                            xml,
                            &xml.path(
                                line,
                                &[
                                    a("TaxTotal"),
                                    b(if matches!(self, LineTax) {
                                        "TaxAmount"
                                    } else {
                                        "RoundingAmount"
                                    }),
                                ],
                            ),
                        )
                    })
            }
            StreetRequired => !standard() || length(xml, &address("StreetName"), 1, 1000, true)?,
            CityRequired => !standard() || length(xml, &address("CityName"), 1, usize::MAX, true)?,
            SimpleNameLength => !simple() || length(xml, &name, 0, 1000, false)?,
            StandardNameLength => !standard() || length(xml, &name, 1, 1000, false)?,
            PaymentNoteLength => length(
                xml,
                &[
                    a("PaymentMeans"),
                    a("PayeeFinancialAccount"),
                    b("PaymentNote"),
                ],
                1,
                1000,
                false,
            )?,
            SimpleStreetLength => !simple() || length(xml, &address("StreetName"), 0, 1000, false)?,
            CityLength => length(xml, &address("CityName"), 0, 127, false)?,
            PaymentCode => {
                let value = normalize_space(&xml.node(node).text);
                !value.contains(' ') && PAYMENT_CODES.contains(&format!(" {value} "))
            }
            BuyerAddress => {
                if !standard() {
                    return Ok(true);
                }
                length(xml, &address("StreetName"), 1, usize::MAX, true)?
                    && length(xml, &address("CityName"), 1, usize::MAX, true)?
                    && length(
                        xml,
                        &buyer_path(&[a("PostalAddress"), a("Country"), b("IdentificationCode")]),
                        1,
                        usize::MAX,
                        true,
                    )?
            }
            AccountLength => length(
                xml,
                &[a("PaymentMeans"), a("PayeeFinancialAccount"), b("ID")],
                0,
                127,
                false,
            )?,
            SupplyDate => nonempty_normalized(
                xml,
                &xml.all_path(&[a("Delivery"), b("ActualDeliveryDate")]),
            )?,
            MissingPayment | MissingReference => false,
            NoteReason => !xml.path(node, &[b("InstructionNote")]).is_empty(),
            NoteReasonLength => (1..=1000).contains(&xml.node(node).text.chars().count()),
            NoteReference => any_nonempty(
                xml,
                &xml.path(node, &[a("InvoiceDocumentReference"), b("ID")]),
            ),
            NoteReferenceLength => {
                let values = xml.path(node, &[a("InvoiceDocumentReference"), b("ID")]);
                values.is_empty()
                    || (1..=5000)
                        .contains(&xml.singleton_text(&values)?.unwrap_or("").chars().count())
            }
            SimpleBuyer => {
                let reasons = xml.all_path(&[
                    a("TaxTotal"),
                    a("TaxSubtotal"),
                    a("TaxCategory"),
                    b("TaxExemptionReasonCode"),
                ]);
                let every = reasons
                    .iter()
                    .all(|&n| " VATEX-SA-HEA VATEX-SA-EDU ".contains(&xml.node(n).text));
                reasons.is_empty() || !every || any_nonempty(xml, &xml.all_path(&name))
            }
            SimpleFlags => {
                let flags: Vec<_> = xml
                    .attribute(node, "", "name")
                    .unwrap_or("")
                    .chars()
                    .collect();
                flags.len() >= 7
                    && flags[2..6].iter().all(|c| matches!(c, '0' | '1'))
                    && flags[6] == '0'
            }
            Stamp => any_nonempty(xml, &xml.all(CAC, "Signature")),
            SummaryBuyer => {
                if !has_summary(xml) {
                    return Ok(true);
                }
                let parties = xml.all_path(&[a("AccountingCustomerParty"), a("Party")]);
                let names = xml
                    .all_path(&[a("PartyLegalEntity"), b("RegistrationName")])
                    .into_iter()
                    .filter(|&n| {
                        let mut parent = xml.node(n).parent;
                        while let Some(id) = parent {
                            if parties.contains(&id) {
                                return true;
                            }
                            parent = xml.node(id).parent;
                        }
                        false
                    })
                    .collect::<Vec<_>>();
                nonempty_normalized(xml, &names)?
            }
            ExportSelfBilling => {
                xml.attribute(node, "", "name").unwrap_or("").chars().nth(6) != Some('1')
            }
            EmptyBuyerVat => {
                !standard()
                    || nonempty_normalized(
                        xml,
                        &xml.all_path(&buyer_path(&[a("PartyTaxScheme"), b("CompanyID")])),
                    )?
            }
        })
    }
}
fn buyer_path(tail: &[Name]) -> Vec<Name> {
    [a("AccountingCustomerParty"), a("Party")]
        .into_iter()
        .chain(tail.iter().copied())
        .collect()
}
fn any_nonempty(xml: &XmlView, nodes: &[NodeId]) -> bool {
    nodes.iter().any(|&n| !xml.node(n).text.is_empty())
}
fn nonempty_normalized(xml: &XmlView, nodes: &[NodeId]) -> Result<bool, FailureKind> {
    Ok(!normalize_space(xml.singleton_text(nodes)?.unwrap_or("")).is_empty())
}
fn length(
    xml: &XmlView,
    path: &[Name],
    min: usize,
    max: usize,
    required: bool,
) -> Result<bool, FailureKind> {
    let nodes = xml.all_path(path);
    if nodes.is_empty() {
        return Ok(!required);
    }
    Ok((min..=max).contains(&xml.singleton_text(&nodes)?.unwrap_or("").chars().count()))
}
fn transaction(value: &str, summary: bool) -> bool {
    static SIMPLE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"02\p{Nd}{5}").unwrap());
    static SUMMARY: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"02\p{Nd}{3}1\p{Nd}").unwrap());
    if summary {
        SUMMARY.is_match(value)
    } else {
        SIMPLE.is_match(value)
    }
}
pub(super) fn has_summary(xml: &XmlView) -> bool {
    xml.elements().any(|(n, _)| {
        xml.attribute(n, "", "name")
            .is_some_and(|v| transaction(v, true))
    })
}
const PAYMENT_CODES: &str = " 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 70 74 75 76 77 78 91 92 93 94 95 96 97 ZZZ ";
