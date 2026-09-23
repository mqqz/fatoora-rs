//! Code-list predicates from the pinned SDK CEN-EN16931-UBL.xsl.
//! Translated source expressions and lists retain LGPL-3.0 terms; see
//! THIRD_PARTY_NOTICES.md and the business-rules source catalog.
use super::{
    FailureKind,
    xml::{CBC, NodeId, UBL, XmlView, a, b, normalize_space},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum CodeListCheck {
    DocumentType,
    AmountCurrency,
    DocumentCurrency,
    TaxCurrency,
    Country,
    PaymentMeans,
    TaxCategory,
}

const INVOICE_TYPES: &str = " 80 82 84 130 202 203 204 211 295 325 326 380 381 383 384 385 386 387 388 389 390 393 394 395 456 457 527 575 623 633 751 780 935 ";
const CREDIT_NOTE_TYPES: &str = " 81 83 261 262 296 308 396 420 458 532 ";
pub(super) const CURRENCIES: &str = " AED AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BOV BRL BSD BTN BWP BYN BZD CAD CDF CHE CHF CHW CLF CLP CNY COP COU CRC CUC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD GNF GTQ GYD HKD HNL HRK HTG HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS KHR KMF KPW KRW KWD KYD KZT LAK LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRO MUR MVR MWK MXN MXV MYR MZN NAD NGN NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD SCR SDG SEK SGD SHP SLL SOS SRD SSP STD SVC SYP SZL THB TJS TMT TND TOP TRY TTD TWD TZS UAH UGX USD USN UYI UYU UZS VEF VND VUV WST XAF XAG XAU XBA XBB XBC XBD XCD XDR XOF XPD XPF XPT XSU XTS XUA XXX YER ZAR ZMW ZWL ";
const COUNTRIES: &str = " 1A AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XI YE YT ZA ZM ZW ";
const PAYMENT_MEANS: &str = " 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 74 75 76 77 78 91 92 93 94 95 96 97 ZZZ ";
const TAX_CATEGORIES: &str = " AE L M E S Z G O K B ";

const AMOUNT_NAMES: &[&str] = &[
    "Amount",
    "BaseAmount",
    "PriceAmount",
    "TaxAmount",
    "TaxableAmount",
    "LineExtensionAmount",
    "TaxExclusiveAmount",
    "TaxInclusiveAmount",
    "AllowanceTotalAmount",
    "ChargeTotalAmount",
    "PrepaidAmount",
    "PayableRoundingAmount",
    "PayableAmount",
];

impl CodeListCheck {
    pub fn contexts(self, xml: &XmlView) -> Vec<NodeId> {
        use CodeListCheck::*;
        match self {
            DocumentType => xml
                .elements()
                .filter(|(_, node)| {
                    node.namespace == CBC
                        && matches!(node.name.as_str(), "InvoiceTypeCode" | "CreditNoteTypeCode")
                })
                .map(|(id, _)| id)
                .collect(),
            AmountCurrency => xml
                .elements()
                .filter(|(_, node)| {
                    node.namespace == CBC && AMOUNT_NAMES.contains(&node.name.as_str())
                })
                .map(|(id, _)| id)
                .collect(),
            DocumentCurrency => xml.all(CBC, "DocumentCurrencyCode"),
            TaxCurrency => xml.all(CBC, "TaxCurrencyCode"),
            Country => xml.all_path(&[a("Country"), b("IdentificationCode")]),
            PaymentMeans => xml.all_path(&[a("PaymentMeans"), b("PaymentMeansCode")]),
            TaxCategory => {
                if !xml.is(0, UBL, "Invoice") {
                    return Vec::new();
                }
                let mut nodes = xml.path(
                    0,
                    &[a("TaxTotal"), a("TaxSubtotal"), a("TaxCategory"), b("ID")],
                );
                nodes.extend(xml.path(
                    0,
                    &[
                        a("InvoiceLine"),
                        a("TaxTotal"),
                        a("TaxSubtotal"),
                        a("TaxCategory"),
                        b("ID"),
                    ],
                ));
                nodes.extend(xml.path(0, &[a("AllowanceCharge"), a("TaxCategory"), b("ID")]));
                nodes.extend(xml.path(
                    0,
                    &[
                        a("InvoiceLine"),
                        a("Item"),
                        a("ClassifiedTaxCategory"),
                        b("ID"),
                    ],
                ));
                nodes.sort_unstable();
                nodes.dedup();
                nodes
            }
        }
    }

    pub fn passes(self, xml: &XmlView, node: NodeId) -> Result<bool, FailureKind> {
        use CodeListCheck::*;
        let text = &xml.node(node).text;
        Ok(match self {
            DocumentType => {
                (xml.is(node, CBC, "InvoiceTypeCode") && listed(INVOICE_TYPES, text))
                    || (xml.is(node, CBC, "CreditNoteTypeCode") && listed(CREDIT_NOTE_TYPES, text))
            }
            AmountCurrency => {
                // The executable condition guards the reported membership test
                // with string-length(@currencyID) > 0, before normalization.
                let value = xml.attribute(node, "", "currencyID").unwrap_or("");
                value.is_empty() || listed(CURRENCIES, value)
            }
            DocumentCurrency | TaxCurrency => listed(CURRENCIES, text),
            Country => listed(COUNTRIES, text),
            PaymentMeans => listed(PAYMENT_MEANS, text),
            TaxCategory => listed(TAX_CATEGORIES, text),
        })
    }
}

fn listed(list: &str, value: &str) -> bool {
    let normalized = normalize_space(value);
    !normalized.contains(' ') && list.contains(&format!(" {normalized} "))
}
