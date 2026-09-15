//! XML serialization for invoices.
use super::{
    Address, Buyer, FinalizedInvoice, InvoiceData, InvoiceNote, InvoiceType, InvoiceView, LineItem,
    OtherId, Party, PartyRole, Seller, SignedInvoice, VatCategory, VatId,
};
use crate::Decimal;

use helpers::{
    currency_amount, id_with_scheme, id_with_scheme_with_agency, quantity_with_unit,
    vat_category_code,
};
use quick_xml::se::Serializer as QuickXmlSerializer;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use thiserror::Error;

/// Wrapper for serializing invoices to XML.
#[derive(Debug, Clone, Copy)]
pub struct InvoiceXml<'a, T: InvoiceView + ?Sized>(pub &'a T);

/// XML serialization error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InvoiceXmlError {
    #[error("failed to serialize invoice to XML: {source}")]
    Serialize {
        #[source]
        source: crate::Diagnostic,
    },
}

impl InvoiceXmlError {
    /// Shared classification used by bindings.
    pub fn kind(&self) -> crate::ErrorKind {
        crate::ErrorKind::Xml
    }
}

/// XML formatting options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum XmlFormat {
    #[default]
    Compact,
    Pretty {
        indent_char: char,
        indent_size: usize,
    },
}

mod helpers {
    use super::VatCategory;
    use crate::Decimal;
    use serde::ser::{Serialize, SerializeStruct, Serializer};
    use std::fmt::{self, Display, Formatter};

    pub(super) fn vat_category_code(category: &VatCategory) -> &'static str {
        match category {
            VatCategory::Exempt => "E",
            VatCategory::Standard => "S",
            VatCategory::Zero => "Z",
            VatCategory::OutOfScope => "O",
        }
    }

    pub(super) struct FixedPrecision {
        value: Decimal,
        precision: usize,
    }

    impl FixedPrecision {
        pub(super) fn new(value: Decimal, precision: usize) -> Self {
            Self { value, precision }
        }
    }

    impl Display for FixedPrecision {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str(&self.value.fixed(self.precision))
        }
    }

    impl Serialize for FixedPrecision {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.collect_str(self)
        }
    }

    struct CurrencyAmountSer<'a> {
        tag: &'static str,
        currency: &'a str,
        value: Decimal,
        precision: usize,
    }

    pub(super) fn currency_amount<'a>(
        tag: &'static str,
        currency: &'a str,
        value: Decimal,
    ) -> impl Serialize + 'a {
        CurrencyAmountSer {
            tag,
            currency,
            value,
            precision: 2,
        }
    }

    impl<'a> Serialize for CurrencyAmountSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut st = s.serialize_struct(self.tag, 2)?;
            st.serialize_field("@currencyID", self.currency)?;
            st.serialize_field("$text", &FixedPrecision::new(self.value, self.precision))?;
            st.end()
        }
    }

    struct IdWithSchemeSer<'a> {
        tag: &'static str,
        scheme_id: &'a str,
        scheme_agency_id: Option<&'a str>,
        value: &'a str,
    }

    pub(super) fn id_with_scheme<'a>(
        tag: &'static str,
        scheme_id: &'a str,
        value: &'a str,
    ) -> impl Serialize + 'a {
        IdWithSchemeSer {
            tag,
            scheme_id,
            scheme_agency_id: None,
            value,
        }
    }

    pub(super) fn id_with_scheme_with_agency<'a>(
        tag: &'static str,
        scheme_id: &'a str,
        scheme_agency_id: &'a str,
        value: &'a str,
    ) -> impl Serialize + 'a {
        IdWithSchemeSer {
            tag,
            scheme_id,
            scheme_agency_id: Some(scheme_agency_id),
            value,
        }
    }

    impl<'a> Serialize for IdWithSchemeSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut st = s.serialize_struct(self.tag, 3)?;
            st.serialize_field("@schemeID", self.scheme_id)?;
            if let Some(agency) = self.scheme_agency_id {
                st.serialize_field("@schemeAgencyID", agency)?;
            }
            st.serialize_field("$text", self.value)?;
            st.end()
        }
    }

    struct QuantityWithUnitSer<'a> {
        tag: &'static str,
        value: Decimal,
        unit_code: &'a str,
    }

    pub(super) fn quantity_with_unit<'a>(
        tag: &'static str,
        value: Decimal,
        unit_code: &'a str,
    ) -> impl Serialize + 'a {
        QuantityWithUnitSer {
            tag,
            value,
            unit_code,
        }
    }

    impl<'a> Serialize for QuantityWithUnitSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut st = s.serialize_struct(self.tag, 2)?;
            st.serialize_field("@unitCode", self.unit_code)?;
            st.serialize_field("$text", &self.value)?;
            st.end()
        }
    }
}

pub(crate) mod constants;
pub mod parse;

struct InvoiceTotals<'a> {
    currency: &'a str,
    vat_percent: Decimal,
    vat_category: &'a VatCategory,
    totals: &'a super::InvoiceTotalsData,
}

impl<'a> InvoiceTotals<'a> {
    fn new<T: InvoiceView + ?Sized>(inv: &'a T) -> Self {
        let data = inv.data();
        let vat_percent = data.adjustment_vat_rate.unwrap_or_else(|| {
            data.line_items
                .iter()
                .find(|li| li.vat_category == data.vat_category)
                .map(|li| li.vat_rate)
                .unwrap_or_default()
        });

        Self {
            currency: data.currency.as_str(),
            vat_percent,
            vat_category: &data.vat_category,
            totals: inv.totals(),
        }
    }

    fn currency(&self) -> &'a str {
        self.currency
    }

    fn taxable_amount(&self) -> Decimal {
        self.totals.taxable_amount()
    }

    fn tax_inclusive_amount(&self) -> Decimal {
        self.totals.tax_inclusive_amount()
    }

    fn line_extension(&self) -> Decimal {
        self.totals.line_extension()
    }

    fn tax_amount(&self) -> Decimal {
        self.totals.tax_amount()
    }

    fn allowance_total(&self) -> Decimal {
        self.totals.allowance_total()
    }

    fn charge_total(&self) -> Decimal {
        self.totals.charge_total()
    }

    fn vat_percent(&self) -> Decimal {
        self.vat_percent
    }

    fn vat_category(&self) -> &'a VatCategory {
        self.vat_category
    }
}

struct InvoiceTypeView<'a>(&'a InvoiceType);

impl<'a> Serialize for InvoiceTypeView<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (attribute_code, body_code) = match self.0 {
            InvoiceType::Tax(st) => match st {
                super::InvoiceSubType::Simplified => ("0200000", "388"),
                super::InvoiceSubType::Standard => ("0100000", "388"),
            },
            InvoiceType::Prepayment(st) => match st {
                super::InvoiceSubType::Simplified => ("0200000", "386"),
                super::InvoiceSubType::Standard => ("0100000", "386"),
            },
            InvoiceType::CreditNote(st, _, _) => match st {
                super::InvoiceSubType::Simplified => ("0200000", "381"),
                super::InvoiceSubType::Standard => ("0100000", "381"),
            },
            InvoiceType::DebitNote(st, _, _) => match st {
                super::InvoiceSubType::Simplified => ("0200000", "383"),
                super::InvoiceSubType::Standard => ("0100000", "383"),
            },
        };

        let mut st = s.serialize_struct("cbc:InvoiceTypeCode", 2)?;
        st.serialize_field("@name", &attribute_code)?;
        st.serialize_field("$text", &body_code)?;
        st.end()
    }
}

struct TaxSchemeXml;

impl Serialize for TaxSchemeXml {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cac:TaxScheme", 0)?;
        st.serialize_field(
            "cbc:ID",
            &id_with_scheme_with_agency("cbc:ID", "UN/ECE 5153", "6", "VAT"),
        )?;
        st.end()
    }
}

struct VatSchemeXml<'a>(&'a VatId);

impl<'a> Serialize for VatSchemeXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vat = self.0;
        let mut st = s.serialize_struct("cac:PartyTaxScheme", 0)?;
        st.serialize_field("cbc:CompanyID", vat.as_str())?;
        st.serialize_field("cac:TaxScheme", &TaxSchemeXml)?;
        st.end()
    }
}

struct PartyXml<'a, R: PartyRole>(&'a Party<R>);

struct PartyIdentificationXml<'a>(&'a OtherId);

impl<'a> Serialize for PartyIdentificationXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let other_id = self.0;
        let mut st = s.serialize_struct("cac:PartyIdentification", 0)?;
        if let Some(scheme_id) = other_id.scheme_id() {
            st.serialize_field(
                "cbc:ID",
                &id_with_scheme("cbc:ID", scheme_id, other_id.as_str()),
            )?;
        } else {
            st.serialize_field("cbc:ID", other_id.as_str())?;
        }
        st.end()
    }
}

struct PartyLegalEntityXml<'a>(&'a str);

impl<'a> Serialize for PartyLegalEntityXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cac:PartyLegalEntity", 0)?;
        st.serialize_field("cbc:RegistrationName", self.0)?;
        st.end()
    }
}

struct AccountingSupplierPartyXml<'a>(&'a Seller);

impl<'a> Serialize for AccountingSupplierPartyXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cac:AccountingSupplierParty", 0)?;
        st.serialize_field("cac:Party", &PartyXml(self.0))?;
        st.end()
    }
}

struct AccountingCustomerPartyXml<'a>(Option<&'a Buyer>);

impl<'a> Serialize for AccountingCustomerPartyXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cac:AccountingCustomerParty", 0)?;
        if let Some(party) = self.0 {
            st.serialize_field("cac:Party", &PartyXml(party))?;
        } else {
            st.serialize_field("cac:Party", &EmptyParty)?;
        }
        st.end()
    }
}

struct EmptyParty;

impl Serialize for EmptyParty {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let st = s.serialize_struct("cac:Party", 0)?;
        st.end()
    }
}

struct NoteXml<'a>(&'a InvoiceNote);

impl<'a> Serialize for NoteXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let note = self.0;
        let mut st = s.serialize_struct("cbc:Note", 2)?;
        st.serialize_field("@languageID", &note.language)?;
        st.serialize_field("$text", &note.text)?;
        st.end()
    }
}

struct EmbeddedDocumentXml<'a> {
    mime_code: &'a str,
    data: &'a str,
}

impl<'a> Serialize for EmbeddedDocumentXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cbc:EmbeddedDocumentBinaryObject", 2)?;
        st.serialize_field("@mimeCode", self.mime_code)?;
        st.serialize_field("$text", self.data)?;
        st.end()
    }
}

enum AdditionalDocumentReferenceXml<'a> {
    InvoiceCounter(&'a str),
    PreviousInvoiceHash(&'a str),
    QrCode(&'a str),
}

struct BillingReferenceXml<'a>(&'a super::OriginalInvoiceRef);

struct InvoiceDocumentReferenceXml<'a>(&'a super::OriginalInvoiceRef);

impl<'a> Serialize for InvoiceDocumentReferenceXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cac:InvoiceDocumentReference", 0)?;
        st.serialize_field("cbc:ID", self.0.id())?;
        if let Some(uuid) = self.0.uuid() {
            st.serialize_field("cbc:UUID", uuid)?;
        }
        if let Some(issue_date) = self.0.issue_date() {
            st.serialize_field("cbc:IssueDate", issue_date.as_str())?;
        }
        st.end()
    }
}

impl<'a> Serialize for BillingReferenceXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cac:BillingReference", 0)?;
        st.serialize_field(
            "cac:InvoiceDocumentReference",
            &InvoiceDocumentReferenceXml(self.0),
        )?;
        st.end()
    }
}

impl<'a> Serialize for AdditionalDocumentReferenceXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cac:AdditionalDocumentReference", 0)?;
        match self {
            AdditionalDocumentReferenceXml::InvoiceCounter(value) => {
                st.serialize_field("cbc:ID", "ICV")?;
                st.serialize_field("cbc:UUID", value)?;
            }
            AdditionalDocumentReferenceXml::PreviousInvoiceHash(value) => {
                st.serialize_field("cbc:ID", "PIH")?;
                st.serialize_field(
                    "cac:Attachment",
                    &AttachmentXml {
                        mime_code: "text/plain",
                        data: value,
                    },
                )?;
            }
            AdditionalDocumentReferenceXml::QrCode(value) => {
                st.serialize_field("cbc:ID", "QR")?;
                st.serialize_field(
                    "cac:Attachment",
                    &AttachmentXml {
                        mime_code: "text/plain",
                        data: value,
                    },
                )?;
            }
        }
        st.end()
    }
}

struct AttachmentXml<'a> {
    mime_code: &'a str,
    data: &'a str,
}

impl<'a> Serialize for AttachmentXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cac:Attachment", 0)?;
        st.serialize_field(
            "cbc:EmbeddedDocumentBinaryObject",
            &EmbeddedDocumentXml {
                mime_code: self.mime_code,
                data: self.data,
            },
        )?;
        st.end()
    }
}

struct TaxCategoryXml<'a> {
    category: &'a VatCategory,
    percent: Decimal,
}

impl<'a> Serialize for TaxCategoryXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cac:TaxCategory", 0)?;
        st.serialize_field(
            "cbc:ID",
            &id_with_scheme_with_agency(
                "cbc:ID",
                "UN/ECE 5305",
                "6",
                vat_category_code(self.category),
            ),
        )?;
        st.serialize_field("cbc:Percent", &self.percent)?;
        st.serialize_field("cac:TaxScheme", &TaxSchemeXml)?;
        st.end()
    }
}

#[derive(Clone)]
struct TaxSubtotalData<'a> {
    taxable_amount: Decimal,
    tax_amount: Decimal,
    currency: &'a str,
    category: &'a VatCategory,
    percent: Decimal,
}

fn allowance_charge<'a>(
    charge_indicator: bool,
    amount: Decimal,
    currency: &'a str,
    reason: &'a str,
    vat_category: &'a VatCategory,
    percent: Decimal,
) -> impl Serialize + 'a {
    struct AllowanceChargeSer<'a> {
        charge_indicator: bool,
        amount: Decimal,
        currency: &'a str,
        reason: &'a str,
        vat_category: &'a VatCategory,
        percent: Decimal,
    }
    impl<'a> Serialize for AllowanceChargeSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut st = s.serialize_struct("cac:AllowanceCharge", 0)?;
            st.serialize_field("cbc:ChargeIndicator", &self.charge_indicator)?;
            st.serialize_field("cbc:AllowanceChargeReason", self.reason)?;
            st.serialize_field(
                "cbc:Amount",
                &currency_amount("cbc:Amount", self.currency, self.amount),
            )?;
            st.serialize_field(
                "cac:TaxCategory",
                &TaxCategoryXml {
                    category: self.vat_category,
                    percent: self.percent,
                },
            )?;
            st.end()
        }
    }
    AllowanceChargeSer {
        charge_indicator,
        amount,
        currency,
        reason,
        vat_category,
        percent,
    }
}

fn tax_total<'a>(
    amount: Decimal,
    currency: &'a str,
    subtotal: Vec<TaxSubtotalData<'a>>,
) -> impl Serialize + 'a {
    struct TaxTotalSer<'a> {
        amount: Decimal,
        currency: &'a str,
        subtotal: Vec<TaxSubtotalData<'a>>,
    }
    impl<'a> Serialize for TaxTotalSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut st = s.serialize_struct("cac:TaxTotal", 0)?;
            st.serialize_field(
                "cbc:TaxAmount",
                &currency_amount("cbc:TaxAmount", self.currency, self.amount),
            )?;
            for subtotal in &self.subtotal {
                st.serialize_field("cac:TaxSubtotal", &tax_subtotal(subtotal.clone()))?;
            }
            st.end()
        }
    }
    TaxTotalSer {
        amount,
        currency,
        subtotal,
    }
}

fn tax_subtotal<'a>(data: TaxSubtotalData<'a>) -> impl Serialize + 'a {
    struct TaxSubtotalSer<'a> {
        data: TaxSubtotalData<'a>,
    }
    impl<'a> Serialize for TaxSubtotalSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let data = &self.data;
            let mut st = s.serialize_struct("cac:TaxSubtotal", 0)?;
            st.serialize_field(
                "cbc:TaxableAmount",
                &currency_amount("cbc:TaxableAmount", data.currency, data.taxable_amount),
            )?;
            st.serialize_field(
                "cbc:TaxAmount",
                &currency_amount("cbc:TaxAmount", data.currency, data.tax_amount),
            )?;
            st.serialize_field(
                "cac:TaxCategory",
                &TaxCategoryXml {
                    category: data.category,
                    percent: data.percent,
                },
            )?;
            st.end()
        }
    }
    TaxSubtotalSer { data }
}

fn legal_monetary_total<'a>(
    currency: &'a str,
    totals: &super::InvoiceTotalsData,
) -> impl Serialize + 'a {
    struct LegalMonetaryTotalSer<'a> {
        currency: &'a str,
        line_extension: Decimal,
        tax_exclusive: Decimal,
        tax_inclusive: Decimal,
        allowance_total: Decimal,
        charge_total: Decimal,
        prepaid: Decimal,
        payable_rounding: Decimal,
        payable: Decimal,
    }
    impl<'a> Serialize for LegalMonetaryTotalSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut st = s.serialize_struct("cac:LegalMonetaryTotal", 0)?;
            st.serialize_field(
                "cbc:LineExtensionAmount",
                &currency_amount(
                    "cbc:LineExtensionAmount",
                    self.currency,
                    self.line_extension,
                ),
            )?;
            st.serialize_field(
                "cbc:TaxExclusiveAmount",
                &currency_amount("cbc:TaxExclusiveAmount", self.currency, self.tax_exclusive),
            )?;
            st.serialize_field(
                "cbc:TaxInclusiveAmount",
                &currency_amount("cbc:TaxInclusiveAmount", self.currency, self.tax_inclusive),
            )?;
            st.serialize_field(
                "cbc:AllowanceTotalAmount",
                &currency_amount(
                    "cbc:AllowanceTotalAmount",
                    self.currency,
                    self.allowance_total,
                ),
            )?;
            st.serialize_field(
                "cbc:ChargeTotalAmount",
                &currency_amount("cbc:ChargeTotalAmount", self.currency, self.charge_total),
            )?;
            st.serialize_field(
                "cbc:PrepaidAmount",
                &currency_amount("cbc:PrepaidAmount", self.currency, self.prepaid),
            )?;
            st.serialize_field(
                "cbc:PayableRoundingAmount",
                &currency_amount(
                    "cbc:PayableRoundingAmount",
                    self.currency,
                    self.payable_rounding,
                ),
            )?;
            st.serialize_field(
                "cbc:PayableAmount",
                &currency_amount("cbc:PayableAmount", self.currency, self.payable),
            )?;
            st.end()
        }
    }
    LegalMonetaryTotalSer {
        currency,
        line_extension: totals.line_extension(),
        tax_exclusive: totals.taxable_amount(),
        tax_inclusive: totals.tax_inclusive_amount(),
        allowance_total: totals.allowance_total(),
        charge_total: totals.charge_total(),
        prepaid: totals.prepaid_amount(),
        payable_rounding: totals.payable_rounding_amount(),
        payable: totals.payable_amount(),
    }
}

fn invoice_line_tax_total<'a>(
    currency: &'a str,
    tax_amount: Decimal,
    rounding_amount: Decimal,
) -> impl Serialize + 'a {
    struct InvoiceLineTaxTotalSer<'a> {
        currency: &'a str,
        tax_amount: Decimal,
        rounding_amount: Decimal,
    }
    impl<'a> Serialize for InvoiceLineTaxTotalSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut st = s.serialize_struct("cac:TaxTotal", 0)?;
            st.serialize_field(
                "cbc:TaxAmount",
                &currency_amount("cbc:TaxAmount", self.currency, self.tax_amount),
            )?;
            st.serialize_field(
                "cbc:RoundingAmount",
                &currency_amount("cbc:RoundingAmount", self.currency, self.rounding_amount),
            )?;
            st.end()
        }
    }
    InvoiceLineTaxTotalSer {
        currency,
        tax_amount,
        rounding_amount,
    }
}

fn invoice_item<'a>(
    description: &'a str,
    vat_category: &'a VatCategory,
    vat_rate: Decimal,
) -> impl Serialize + 'a {
    struct InvoiceItemSer<'a> {
        description: &'a str,
        vat_category: &'a VatCategory,
        vat_rate: Decimal,
    }
    impl<'a> Serialize for InvoiceItemSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut st = s.serialize_struct("cac:Item", 0)?;
            st.serialize_field("cbc:Name", self.description)?;
            st.serialize_field(
                "cac:ClassifiedTaxCategory",
                &TaxCategoryXml {
                    category: self.vat_category,
                    percent: self.vat_rate,
                },
            )?;
            st.end()
        }
    }
    InvoiceItemSer {
        description,
        vat_category,
        vat_rate,
    }
}

#[derive(serde::Serialize)]
struct ExactPrice<'a> {
    #[serde(rename = "@currencyID")]
    currency: &'a str,
    #[serde(rename = "$text")]
    value: Decimal,
}
fn invoice_line_price<'a>(currency: &'a str, unit_price: Decimal) -> impl Serialize + 'a {
    struct InvoiceLinePriceSer<'a> {
        currency: &'a str,
        unit_price: Decimal,
    }
    impl<'a> Serialize for InvoiceLinePriceSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut st = s.serialize_struct("cac:Price", 0)?;
            st.serialize_field(
                "cbc:PriceAmount",
                &ExactPrice {
                    currency: self.currency,
                    value: self.unit_price,
                },
            )?;
            st.end()
        }
    }
    InvoiceLinePriceSer {
        currency,
        unit_price,
    }
}

fn payment_means<'a>(code: &'a str, instruction_note: Option<&'a str>) -> impl Serialize + 'a {
    struct PaymentMeansSer<'a> {
        code: &'a str,
        instruction_note: Option<&'a str>,
    }
    impl<'a> Serialize for PaymentMeansSer<'a> {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut st = s.serialize_struct("cac:PaymentMeans", 0)?;
            st.serialize_field("cbc:PaymentMeansCode", self.code)?;
            if let Some(note) = self.instruction_note {
                st.serialize_field("cbc:InstructionNote", note)?;
            }
            st.end()
        }
    }
    PaymentMeansSer {
        code,
        instruction_note,
    }
}

impl<'a, R: PartyRole> Serialize for PartyXml<'a, R> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let p = self.0;

        let mut st = s.serialize_struct("cac:Party", 0)?;

        if let Some(other_id) = &p.other_id {
            st.serialize_field("cac:PartyIdentification", &PartyIdentificationXml(other_id))?;
        }

        // Identification
        // Address
        st.serialize_field("cac:PostalAddress", &AddressXml(&p.address))?;

        if let Some(vat) = &p.vat_id {
            st.serialize_field("cac:PartyTaxScheme", &VatSchemeXml(vat))?;
        }

        // Legal entity
        st.serialize_field("cac:PartyLegalEntity", &PartyLegalEntityXml(&p.name))?;

        st.end()
    }
}

struct AddressXml<'a>(&'a Address);

impl<'a> Serialize for AddressXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let a = self.0;
        let mut st = s.serialize_struct("cac:PostalAddress", 0)?;

        st.serialize_field("cbc:StreetName", &a.street)?;
        if let Some(additional) = &a.additional_street {
            st.serialize_field("cbc:AdditionalStreetName", additional)?;
        }
        st.serialize_field("cbc:BuildingNumber", &a.building_number)?;
        if let Some(subdivision) = &a.subdivision {
            st.serialize_field("cbc:CitySubdivisionName", subdivision)?;
        }
        st.serialize_field("cbc:CityName", &a.city)?;
        st.serialize_field("cbc:PostalZone", &a.postal_code)?;
        let alpha2 = a.country_code.alpha2();
        st.serialize_field("cac:Country", &CountryXml(&alpha2))?;

        st.end()
    }
}

struct CountryXml<'a>(&'a str);

impl<'a> Serialize for CountryXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = s.serialize_struct("cac:Country", 0)?;
        st.serialize_field("cbc:IdentificationCode", self.0)?;
        st.end()
    }
}

struct InvoiceLineXml<'a>(usize, &'a LineItem, &'a InvoiceData);

impl<'a> Serialize for InvoiceLineXml<'a> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (idx, li, invoice) = (self.0, self.1, self.2);

        let mut st = s.serialize_struct("cac:InvoiceLine", 0)?;

        st.serialize_field("cbc:ID", &idx.to_string())?;

        st.serialize_field(
            "cbc:InvoicedQuantity",
            &quantity_with_unit("cbc:InvoicedQuantity", li.quantity, &li.unit_code),
        )?;
        st.serialize_field(
            "cbc:LineExtensionAmount",
            &currency_amount(
                "cbc:LineExtensionAmount",
                invoice.currency.as_str(),
                li.total_amount,
            ),
        )?;
        st.serialize_field(
            "cac:TaxTotal",
            &invoice_line_tax_total(
                invoice.currency.as_str(),
                li.vat_amount,
                li.total_amount
                    .add(li.vat_amount)
                    .map_err(serde::ser::Error::custom)?,
            ),
        )?;
        st.serialize_field(
            "cac:Item",
            &invoice_item(&li.description, &li.vat_category, li.vat_rate),
        )?;
        st.serialize_field(
            "cac:Price",
            &invoice_line_price(invoice.currency.as_str(), li.unit_price),
        )?;

        st.end()
    }
}

/// Serialize invoices to XML.
///
/// # Examples
/// ```rust,no_run
/// use fatoora_core::invoice::xml::ToXml;
/// use fatoora_core::invoice::FinalizedInvoice;
///
/// let invoice: FinalizedInvoice = unimplemented!();
/// let xml = invoice.to_xml()?;
/// # let _ = xml;
/// # Ok::<(), fatoora_core::invoice::xml::InvoiceXmlError>(())
/// ```
pub trait ToXml {
    fn to_xml_with_format(&self, format: XmlFormat) -> Result<String, InvoiceXmlError>;

    fn to_xml(&self) -> Result<String, InvoiceXmlError> {
        self.to_xml_with_format(XmlFormat::Pretty {
            indent_char: ' ',
            indent_size: 2,
        })
    }

    fn to_xml_pretty(&self) -> Result<String, InvoiceXmlError> {
        self.to_xml_with_format(XmlFormat::Pretty {
            indent_char: ' ',
            indent_size: 2,
        })
    }
}

impl ToXml for FinalizedInvoice {
    fn to_xml_with_format(&self, format: XmlFormat) -> Result<String, InvoiceXmlError> {
        to_xml_with_format(self, format)
    }
}

impl ToXml for SignedInvoice {
    fn to_xml_with_format(&self, format: XmlFormat) -> Result<String, InvoiceXmlError> {
        // FIXME: sort this out properly
        // to_xml_with_format(self, format)
        let _ = format;
        Ok(self.xml().to_string())
    }
}

fn to_xml_with_format<T: InvoiceView + ?Sized>(
    invoice: &T,
    format: XmlFormat,
) -> Result<String, InvoiceXmlError> {
    let mut buffer = String::with_capacity(4096);
    buffer.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    buffer.push('\n');

    {
        let mut serializer = QuickXmlSerializer::new(&mut buffer);
        if let XmlFormat::Pretty {
            indent_char,
            indent_size,
        } = format
        {
            serializer.indent(indent_char, indent_size);
        }
        InvoiceXml(invoice)
            .serialize(serializer)
            .map_err(|error| InvoiceXmlError::Serialize {
                source: crate::Diagnostic::new(error.to_string()),
            })?;
    }

    Ok(buffer)
}

impl<'a, T: InvoiceView + ?Sized> Serialize for InvoiceXml<'a, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let view = self.0;
        let data = view.data();
        let totals = InvoiceTotals::new(view);
        let currency_code = totals.currency();

        let mut root = serializer.serialize_struct("Invoice", 0)?;

        // ---- namespaces (attributes) ----
        root.serialize_field(
            "@xmlns",
            "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
        )?;
        root.serialize_field(
            "@xmlns:cac",
            "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
        )?;
        root.serialize_field(
            "@xmlns:cbc",
            "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
        )?;
        root.serialize_field(
            "@xmlns:ext",
            "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
        )?;

        // ---- identifiers & issue info ----
        root.serialize_field("cbc:ProfileID", "reporting:1.0")?;
        root.serialize_field("cbc:ID", &data.id)?;
        root.serialize_field("cbc:UUID", &data.uuid)?;
        root.serialize_field("cbc:IssueDate", data.issue_datetime.date_str())?;
        root.serialize_field("cbc:IssueTime", data.issue_datetime.time_str())?;

        // ---- invoice type ----
        root.serialize_field("cbc:InvoiceTypeCode", &InvoiceTypeView(&data.invoice_type))?;
        if let Some(note) = data.note.as_ref() {
            root.serialize_field("cbc:Note", &NoteXml(note))?;
        }
        root.serialize_field("cbc:DocumentCurrencyCode", currency_code)?;
        root.serialize_field("cbc:TaxCurrencyCode", currency_code)?;

        // ---- credit/debit references ----
        match &data.invoice_type {
            InvoiceType::CreditNote(_, original, _) | InvoiceType::DebitNote(_, original, _) => {
                root.serialize_field("cac:BillingReference", &BillingReferenceXml(original))?;
            }
            _ => {}
        }

        // ---- supporting references ----
        let counter = data.invoice_counter.to_string();
        root.serialize_field(
            "cac:AdditionalDocumentReference",
            &AdditionalDocumentReferenceXml::InvoiceCounter(&counter),
        )?;
        root.serialize_field(
            "cac:AdditionalDocumentReference",
            &AdditionalDocumentReferenceXml::PreviousInvoiceHash(&data.previous_invoice_hash),
        )?;
        if let Some(qr) = view.qr_code() {
            root.serialize_field(
                "cac:AdditionalDocumentReference",
                &AdditionalDocumentReferenceXml::QrCode(qr),
            )?;
        }

        // ---- parties ----
        root.serialize_field(
            "cac:AccountingSupplierParty",
            &AccountingSupplierPartyXml(&data.seller),
        )?;
        root.serialize_field(
            "cac:AccountingCustomerParty",
            &AccountingCustomerPartyXml(data.buyer.as_ref()),
        )?;

        // ---- payment ----
        let instruction_note = match &data.invoice_type {
            InvoiceType::CreditNote(_, _, reason) | InvoiceType::DebitNote(_, _, reason) => {
                if reason.trim().is_empty() {
                    None
                } else {
                    Some(reason.as_str())
                }
            }
            _ => None,
        };
        root.serialize_field(
            "cac:PaymentMeans",
            &payment_means(&data.payment_means_code, instruction_note),
        )?;

        // ---- allowance / charges ----
        if totals.allowance_total() > Decimal::ZERO || data.allowance_reason.is_some() {
            root.serialize_field(
                "cac:AllowanceCharge",
                &allowance_charge(
                    false,
                    totals.allowance_total(),
                    currency_code,
                    data.allowance_reason.as_deref().unwrap_or("discount"),
                    totals.vat_category(),
                    totals.vat_percent(),
                ),
            )?;
        }
        if totals.charge_total() > Decimal::ZERO {
            root.serialize_field(
                "cac:AllowanceCharge",
                &allowance_charge(
                    true,
                    totals.charge_total(),
                    currency_code,
                    data.allowance_reason.as_deref().unwrap_or("charge"),
                    totals.vat_category(),
                    totals.vat_percent(),
                ),
            )?;
        }

        // ---- tax totals ----
        let tax_subtotals = view
            .totals()
            .vat_breakdown()
            .iter()
            .map(|g| TaxSubtotalData {
                taxable_amount: g.taxable_amount,
                tax_amount: g.tax_amount,
                currency: currency_code,
                category: &g.category,
                percent: g.rate,
            })
            .collect();
        root.serialize_field(
            "cac:TaxTotal",
            &tax_total(totals.tax_amount(), currency_code, Vec::new()),
        )?;
        root.serialize_field(
            "cac:TaxTotal",
            &tax_total(totals.tax_amount(), currency_code, tax_subtotals),
        )?;

        // ---- legal monetary totals ----
        root.serialize_field(
            "cac:LegalMonetaryTotal",
            &legal_monetary_total(currency_code, view.totals()),
        )?;

        // ---- lines ----
        for (i, line) in data.line_items.iter().enumerate() {
            root.serialize_field("cac:InvoiceLine", &InvoiceLineXml(i + 1, line, data))?;
        }

        root.end()
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    use crate::invoice::{
        Address, CountryCode, InvoiceBuilder, InvoiceSubType, InvoiceType, LineItem, Party,
        SellerRole, VatCategory,
    };
    #[test]
    fn test_invoice_xml_serialization() {
        let seller = Party::<SellerRole>::new(
            "Acme Inc".into(),
            Address {
                country_code: CountryCode::parse("SAU").expect("country code"),
                city: "Riyadh".into(),
                street: "King Fahd".into(),
                additional_street: None,
                building_number: "1234".into(),
                additional_number: Some("5678".into()),
                postal_code: "12222".into(),
                subdivision: None,
                district: None,
            },
            "301121971500003",
            None,
        )
        .expect("valid seller");

        let line_item = LineItem::new(
            "Item",
            crate::Decimal::parse("1.0").unwrap(),
            "PCE",
            crate::Decimal::parse("100.0").unwrap(),
            crate::Decimal::parse("15.0").unwrap(),
            VatCategory::Standard,
        )
        .unwrap();

        let mut builder = InvoiceBuilder::new(InvoiceType::Tax(InvoiceSubType::Simplified));
        builder = builder
            .id("INV-1")
            .uuid("uuid-123")
            .issue_datetime("2024-01-01T12:30:00Z")
            .currency("SAR")
            .previous_invoice_hash("hash")
            .invoice_counter(0)
            .seller(seller)
            .payment_means_code("10")
            .vat_category(VatCategory::Standard)
            .line_item(line_item);
        let invoice = builder.build().expect("build invoice");
        let xml_result = invoice.to_xml().unwrap();
        println!("{xml_result:?}");

        let pretty = invoice.to_xml_pretty().unwrap();
        println!("{pretty}");
    }
}
