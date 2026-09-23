//! SDK KSA identity/address predicates; source expressions retain LGPL-3.0.
//! Paths intentionally retain all matches, including global singleton operands.
use super::{
    FailureKind,
    xml::{NodeId, XmlView, a, b, normalize_space},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum IdentityCheck {
    Crn,
    UnifiedId,
    SchemeWhitespace,
    PredictableId,
    BuyerScheme,
    BuyerTin,
    BuyerNationalId,
    BuyerResidenceId,
    SellerStreet,
    SellerAddress,
    BuyerAdditionalStreet,
    SellerCity,
    SellerAdditionalStreet,
    SellerPostcode,
    SellerBuilding,
    SellerVat,
    BuyerVat,
    BuyerPhone,
    ContactName,
    ContactNote,
}

impl IdentityCheck {
    pub fn contexts(self, xml: &XmlView) -> Vec<NodeId> {
        use IdentityCheck::*;
        match self {
            Crn | UnifiedId | SchemeWhitespace | PredictableId => {
                let mut nodes = xml.all_path(&[a("AccountingSupplierParty")]);
                nodes.extend(xml.all_path(&[a("AccountingCustomerParty")]));
                nodes.sort_unstable();
                nodes
            }
            BuyerScheme | BuyerTin | BuyerNationalId | BuyerResidenceId => xml.all_path(&[
                a("AccountingCustomerParty"),
                a("Party"),
                a("PartyIdentification"),
                b("ID"),
            ]),
            SellerStreet
            | SellerAddress
            | BuyerAdditionalStreet
            | SellerCity
            | SellerAdditionalStreet
            | SellerPostcode => {
                xml.all_path(&[a("AccountingSupplierParty"), a("Party"), a("PostalAddress")])
            }
            SellerBuilding => xml.all_path(&[a("AccountingSupplierParty"), a("Party")]),
            SellerVat => {
                if xml
                    .all_path(&[
                        a("AccountingSupplierParty"),
                        a("Party"),
                        a("PartyTaxScheme"),
                        b("CompanyID"),
                    ])
                    .is_empty()
                {
                    return Vec::new();
                }
                xml.all_path(&[
                    a("AccountingSupplierParty"),
                    a("Party"),
                    a("PartyTaxScheme"),
                    a("TaxScheme"),
                ])
                .into_iter()
                .filter(|&id| {
                    xml.path(id, &[b("ID")])
                        .iter()
                        .any(|&id| xml.node(id).text == "VAT")
                })
                .collect()
            }
            BuyerVat => xml.all_path(&[
                a("AccountingCustomerParty"),
                a("Party"),
                a("PartyTaxScheme"),
                b("CompanyID"),
            ]),
            BuyerPhone | ContactName | ContactNote => {
                xml.all_path(&[a("AccountingCustomerParty"), a("Party"), a("Contact")])
            }
        }
    }

    pub fn passes(self, xml: &XmlView, node: NodeId) -> Result<bool, FailureKind> {
        use IdentityCheck::*;
        let text = |path: &[_]| {
            xml.singleton_text(&xml.path(node, path))
                .map(|v| v.unwrap_or(""))
        };
        let global = |path: &[_]| {
            xml.singleton_text(&xml.all_path(path))
                .map(|v| v.unwrap_or(""))
        };
        match self {
            Crn | UnifiedId | SchemeWhitespace | PredictableId => {
                let ids = xml.path(node, &[a("Party"), a("PartyIdentification"), b("ID")]);
                let allowed = if xml.is(node, super::xml::CAC, "AccountingSupplierParty") {
                    &SELLER_SCHEMES[..]
                } else {
                    &BUYER_SCHEMES[..]
                };
                if matches!(self, PredictableId) {
                    return Ok(!ids.iter().any(|&id| {
                        let scheme =
                            normalize_space(xml.attribute(id, "", "schemeID").unwrap_or(""))
                                .to_uppercase();
                        let value = normalize_space(&xml.node(id).text);
                        allowed.contains(&scheme.as_str()) && predictable(&value)
                    }));
                }
                let raw = singleton_attribute(xml, &ids, "schemeID")?;
                let scheme = normalize_space(raw);
                if matches!(self, SchemeWhitespace) {
                    return Ok(raw.is_empty()
                        || !allowed.contains(&scheme.to_uppercase().as_str())
                        || raw == scheme);
                }
                let expected = if matches!(self, Crn) { "CRN" } else { "700" };
                if ids.is_empty() || scheme != expected {
                    return Ok(true);
                }
                let value = xml.singleton_text(&ids)?.unwrap_or("");
                Ok(valid_identifier(
                    value,
                    if matches!(self, Crn) { None } else { Some('7') },
                ))
            }
            BuyerScheme => {
                let scheme = normalize_space(xml.attribute(node, "", "schemeID").unwrap_or(""));
                // The source checks substring membership, including multi-code
                // strings; do not silently tighten this into token membership.
                Ok(scheme.chars().count() > 2
                    && "TIN NAT IQA PAS CRN MOM MLS 700 SAG GCC OTH".contains(&scheme))
            }
            BuyerTin | BuyerNationalId | BuyerResidenceId => {
                let (scheme, prefix) = match self {
                    BuyerTin => ("TIN", '3'),
                    BuyerNationalId => ("NAT", '1'),
                    _ => ("IQA", '2'),
                };
                Ok(
                    normalize_space(xml.attribute(node, "", "schemeID").unwrap_or("")) != scheme
                        || valid_identifier(&xml.node(node).text, Some(prefix)),
                )
            }
            SellerStreet | SellerCity | SellerAdditionalStreet => {
                let (field, min, max) = match self {
                    SellerStreet => ("StreetName", 1, 1000),
                    SellerCity => ("CityName", 1, 127),
                    _ => ("AdditionalStreetName", 0, 127),
                };
                optional_length(xml, &xml.path(node, &[b(field)]), min, max)
            }
            SellerAddress => Ok([
                "StreetName",
                "BuildingNumber",
                "CityName",
                "PostalZone",
                "CitySubdivisionName",
            ]
            .iter()
            .all(|field| !xml.path(node, &[b(field)]).is_empty())
                && !xml
                    .path(node, &[a("Country"), b("IdentificationCode")])
                    .is_empty()),
            BuyerAdditionalStreet => optional_length(
                xml,
                &xml.all_path(&[
                    a("AccountingCustomerParty"),
                    a("Party"),
                    a("PostalAddress"),
                    b("AdditionalStreetName"),
                ]),
                0,
                127,
            ),
            SellerPostcode => Ok(ascii_digits(text(&[b("PostalZone")])?, 5)),
            SellerBuilding => Ok(ascii_digits(
                text(&[a("PostalAddress"), b("BuildingNumber")])?,
                4,
            )),
            SellerVat | BuyerVat => {
                let role = if matches!(self, SellerVat) {
                    "AccountingSupplierParty"
                } else {
                    "AccountingCustomerParty"
                };
                let value = global(&[a(role), a("Party"), a("PartyTaxScheme"), b("CompanyID")])?;
                Ok((matches!(self, BuyerVat) && value.is_empty())
                    || (ascii_digits(value, 15) && value.starts_with('3') && value.ends_with('3')))
            }
            BuyerPhone => {
                let value = global(&[
                    a("AccountingCustomerParty"),
                    a("Party"),
                    a("Contact"),
                    b("Telephone"),
                ])?;
                if value.is_empty() {
                    return Ok(true);
                }
                Ok(value.strip_prefix(['0', '+']).is_some_and(|digits| {
                    (4..=15).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
                }))
            }
            ContactName | ContactNote => optional_length(
                xml,
                &xml.all_path(&[
                    a("AccountingCustomerParty"),
                    a("Party"),
                    a("Contact"),
                    b(if matches!(self, ContactName) {
                        "Name"
                    } else {
                        "Note"
                    }),
                ]),
                0,
                1000,
            ),
        }
    }
}

const SELLER_SCHEMES: [&str; 6] = ["CRN", "MOM", "MLS", "700", "SAG", "OTH"];
const BUYER_SCHEMES: [&str; 11] = [
    "TIN", "CRN", "MOM", "MLS", "700", "SAG", "NAT", "GCC", "IQA", "OTH", "PAS",
];

pub(super) fn singleton_attribute<'a>(
    xml: &'a XmlView,
    nodes: &[NodeId],
    name: &str,
) -> Result<&'a str, FailureKind> {
    let mut attributes = nodes.iter().filter_map(|&id| xml.attribute(id, "", name));
    let value = attributes.next().unwrap_or("");
    if attributes.next().is_some() {
        return Err(FailureKind::Cardinality);
    }
    Ok(value)
}

pub(super) fn optional_length(
    xml: &XmlView,
    nodes: &[NodeId],
    min: usize,
    max: usize,
) -> Result<bool, FailureKind> {
    Ok(xml
        .singleton_text(nodes)?
        .is_none_or(|value| (min..=max).contains(&value.chars().count())))
}

fn ascii_digits(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_digit())
}
fn valid_identifier(value: &str, prefix: Option<char>) -> bool {
    ascii_digits(value, 10) && prefix.is_none_or(|p| value.starts_with(p))
}
fn predictable(value: &str) -> bool {
    // XPath \d denotes Unicode decimal digits; matching the ASCII sequences
    // below still requires those exact code points.
    static DIGITS: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^\p{Nd}+$").expect("constant regex"));
    DIGITS.is_match(value)
        && [
            "01234567", "12345678", "23456789", "76543210", "87654321", "98765432", "00000000",
            "11111111", "22222222", "33333333", "44444444", "55555555", "66666666", "77777777",
            "88888888", "99999999",
        ]
        .iter()
        .any(|p| value.contains(p))
}
