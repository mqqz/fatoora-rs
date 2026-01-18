//! XML parsing for invoices.
use crate::invoice::sign::SignedProperties;
use crate::invoice::xml::constants::{CAC_NS, CBC_NS, DS_NS, INVOICE_NS, XADES_NS};
use crate::invoice::{
    Address, FinalizedInvoice, InvoiceBuilder, InvoiceSubType, InvoiceType, LineItem,
    LineItemPartsFields,
    OriginalInvoiceRef, OtherId, Party, SellerRole, SignedInvoice, VatCategory,
};
use base64ct::{Base64, Encoding};
use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use iso_currency::Currency;
use isocountry::CountryCode;
use libxml::{parser::Parser, tree::Document, xpath};
use std::path::Path;
use thiserror::Error;

/// Errors emitted while parsing XML invoices.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("XML parse error: {0}")]
    XmlParse(String),
    #[error("XPath error: {0}")]
    XPath(String),
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("Invalid value for {field}: {value}")]
    InvalidValue { field: &'static str, value: String },
}

/// Parse a finalized invoice from XML string.
///
/// # Examples
/// ```rust,no_run
/// use fatoora_core::invoice::xml::parse::parse_finalized_invoice_xml;
///
/// let xml = std::fs::read_to_string("invoice.xml")?;
/// let invoice = parse_finalized_invoice_xml(&xml)?;
/// # let _ = invoice;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_finalized_invoice_xml(xml: &str) -> Result<FinalizedInvoice, ParseError> {
    let doc = Parser::default()
        .parse_string(xml)
        .map_err(|e| ParseError::XmlParse(format!("{e:?}")))?;
    parse_finalized_invoice_doc(&doc)
}

/// Parse a finalized invoice from an XML file.
pub fn parse_finalized_invoice_xml_file(path: &Path) -> Result<FinalizedInvoice, ParseError> {
    let xml = std::fs::read_to_string(path).map_err(|e| ParseError::XmlParse(format!("{e:?}")))?;
    parse_finalized_invoice_xml(&xml)
}

/// Parse a signed invoice from XML string.
pub fn parse_signed_invoice_xml(xml: &str) -> Result<SignedInvoice, ParseError> {
    let doc = Parser::default()
        .parse_string(xml)
        .map_err(|e| ParseError::XmlParse(format!("{e:?}")))?;
    let finalized = parse_finalized_invoice_doc(&doc)?;
    let signing = parse_signed_properties(&doc)?;
    let signed = finalized
        .sign_with_bundle(signing, xml.to_string())
        .map_err(|e| ParseError::XmlParse(format!("{e:?}")))?;
    Ok(signed)
}

/// Parse a signed invoice from an XML file.
pub fn parse_signed_invoice_xml_file(path: &Path) -> Result<SignedInvoice, ParseError> {
    let xml = std::fs::read_to_string(path).map_err(|e| ParseError::XmlParse(format!("{e:?}")))?;
    parse_signed_invoice_xml(&xml)
}

fn parse_finalized_invoice_doc(doc: &Document) -> Result<FinalizedInvoice, ParseError> {
    let ctx = build_context(doc)?;

    let id = xpath_text_required(&ctx, "/ubl:Invoice/cbc:ID", "ID")?;
    let uuid = xpath_text_required(&ctx, "/ubl:Invoice/cbc:UUID", "UUID")?;
    let issue_date = xpath_text_required(&ctx, "/ubl:Invoice/cbc:IssueDate", "IssueDate")?;
    let issue_time = xpath_text_required(&ctx, "/ubl:Invoice/cbc:IssueTime", "IssueTime")?;
    let invoice_type_code =
        xpath_text_required(&ctx, "/ubl:Invoice/cbc:InvoiceTypeCode", "InvoiceTypeCode")?;
    let invoice_type_name = xpath_text_required(
        &ctx,
        "/ubl:Invoice/cbc:InvoiceTypeCode/@name",
        "InvoiceTypeCode@name",
    )?;
    let currency_code = xpath_text_required(
        &ctx,
        "/ubl:Invoice/cbc:DocumentCurrencyCode",
        "DocumentCurrencyCode",
    )?;
    let payment_means_code = xpath_text_required(
        &ctx,
        "/ubl:Invoice/cac:PaymentMeans/cbc:PaymentMeansCode",
        "PaymentMeansCode",
    )?;

    let issue_datetime = parse_datetime(&issue_date, &issue_time)?;
    let currency = Currency::from_code(&currency_code).ok_or(ParseError::InvalidValue {
        field: "DocumentCurrencyCode",
        value: currency_code,
    })?;
    let original_ref = if invoice_type_code == "381" || invoice_type_code == "383" {
        Some(parse_original_ref(&ctx)?)
    } else {
        None
    };
    let reason = xpath_text_optional(&ctx, "/ubl:Invoice/cac:PaymentMeans/cbc:InstructionNote")?
        .or_else(|| {
            xpath_text_optional(&ctx, "/ubl:Invoice/cbc:Note")
                .ok()
                .flatten()
        });
    let invoice_type = parse_invoice_type(
        &invoice_type_name,
        &invoice_type_code,
        original_ref,
        reason.unwrap_or_default(),
    )?;

    let seller = parse_seller(&ctx)?;

    let previous_invoice_hash = xpath_text_required(
        &ctx,
        "/ubl:Invoice/cac:AdditionalDocumentReference[cbc:ID='PIH']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject",
        "PIH",
    )?;

    let vat_category = parse_vat_category(&ctx)?;
    let line_items = parse_line_items(&ctx)?;
    let invoice_counter_str = xpath_text_required(
        &ctx,
        "/ubl:Invoice/cac:AdditionalDocumentReference[cbc:ID='ICV']/cbc:UUID",
        "ICV",
    )?;
    let invoice_counter =
        invoice_counter_str
            .parse::<u64>()
            .map_err(|_| ParseError::InvalidValue {
                field: "ICV",
                value: invoice_counter_str,
            })?;

    let mut builder = InvoiceBuilder::new(crate::invoice::RequiredInvoiceFields {
        invoice_type,
        id,
        uuid,
        issue_datetime,
        currency,
        previous_invoice_hash,
        invoice_counter,
        seller,
        line_items,
        payment_means_code,
        vat_category,
    });
    if let Some(note) = xpath_text_optional(&ctx, "/ubl:Invoice/cbc:Note")? {
        let language = xpath_text_optional(&ctx, "/ubl:Invoice/cbc:Note/@languageID")?
            .unwrap_or_else(|| "en".to_string());
        builder.note(crate::invoice::InvoiceNote {
            language,
            text: note,
        });
    }
    if let Some(reason) = xpath_text_optional(
        &ctx,
        "/ubl:Invoice/cac:AllowanceCharge/cbc:AllowanceChargeReason",
    )? {
        let amount = xpath_text_optional(&ctx, "/ubl:Invoice/cac:AllowanceCharge/cbc:Amount")?
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        builder
            .invoice_level_discount(amount)
            .allowance_reason(reason);
    }

    builder
        .build()
        .map_err(|e| ParseError::XmlParse(format!("{e:?}")))
}

fn parse_signed_properties(doc: &Document) -> Result<SignedProperties, ParseError> {
    let ctx = build_context(doc)?;
    ctx.register_namespace("ds", DS_NS)
        .map_err(|e| ParseError::XPath(format!("{e:?}")))?;
    ctx.register_namespace("xades", XADES_NS)
        .map_err(|e| ParseError::XPath(format!("{e:?}")))?;

    let qr = xpath_text_required(
        &ctx,
        "/ubl:Invoice/cac:AdditionalDocumentReference[cbc:ID='QR']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject",
        "QR",
    )?;
    let qr_fields = decode_qr_tlv(&qr)?;

    let invoice_hash = qr_fields
        .get(&6)
        .and_then(bytes_to_string)
        .ok_or(ParseError::MissingField("QR tag 6 (invoice hash)"))?;
    let signature = qr_fields
        .get(&7)
        .and_then(bytes_to_string)
        .ok_or(ParseError::MissingField("QR tag 7 (signature)"))?;
    let public_key = qr_fields
        .get(&8)
        .map(|v| Base64::encode_string(v))
        .ok_or(ParseError::MissingField("QR tag 8 (public key)"))?;
    let zatca_key_signature = qr_fields.get(&9).map(|v| Base64::encode_string(v));

    let signing_time = xpath_text_required(
        &ctx,
        "//*[local-name()='SignedProperties']//*[local-name()='SigningTime']",
        "SigningTime",
    )?;
    let signing_time = chrono::NaiveDateTime::parse_from_str(&signing_time, "%Y-%m-%dT%H:%M:%S")
        .map_err(|e| ParseError::InvalidValue {
            field: "SigningTime",
            value: format!("{signing_time} ({e:?})"),
        })?;
    let signing_time = chrono::DateTime::from_naive_utc_and_offset(signing_time, Utc);

    let cert_hash = xpath_text_required(
        &ctx,
        "//*[local-name()='CertDigest']//*[local-name()='DigestValue']",
        "CertDigest",
    )?;
    let issuer = xpath_text_required(
        &ctx,
        "//*[local-name()='IssuerSerial']//*[local-name()='X509IssuerName']",
        "IssuerName",
    )?;
    let serial = xpath_text_required(
        &ctx,
        "//*[local-name()='IssuerSerial']//*[local-name()='X509SerialNumber']",
        "SerialNumber",
    )?;
    let signed_props_hash = xpath_text_required(
        &ctx,
        "//*[local-name()='SignedInfo']//*[local-name()='Reference'][@URI='#xadesSignedProperties']//*[local-name()='DigestValue']",
        "SignedPropertiesDigest",
    )?;

    Ok(SignedProperties {
        invoice_hash,
        signature,
        public_key,
        issuer,
        serial,
        cert_hash,
        signed_props_hash,
        signing_time,
        zatca_key_signature,
    })
}

fn parse_invoice_type(
    name_code: &str,
    body_code: &str,
    original_ref: Option<OriginalInvoiceRef>,
    reason: String,
) -> Result<InvoiceType, ParseError> {
    let reason = if reason.trim().is_empty() {
        "Adjustment".to_string()
    } else {
        reason
    };
    let subtype = if name_code.starts_with("02") {
        InvoiceSubType::Simplified
    } else if name_code.starts_with("01") {
        InvoiceSubType::Standard
    } else {
        return Err(ParseError::InvalidValue {
            field: "InvoiceTypeCode@name",
            value: name_code.to_string(),
        });
    };

    match body_code {
        "388" => Ok(InvoiceType::Tax(subtype)),
        "386" => Ok(InvoiceType::Prepayment(subtype)),
        "381" => Ok(InvoiceType::CreditNote(
            subtype,
            original_ref.ok_or(ParseError::MissingField("BillingReference"))?,
            reason,
        )),
        "383" => Ok(InvoiceType::DebitNote(
            subtype,
            original_ref.ok_or(ParseError::MissingField("BillingReference"))?,
            reason,
        )),
        _ => Err(ParseError::InvalidValue {
            field: "InvoiceTypeCode",
            value: body_code.to_string(),
        }),
    }
}

fn parse_original_ref(ctx: &xpath::Context) -> Result<OriginalInvoiceRef, ParseError> {
    let id = xpath_text_required(
        ctx,
        "/ubl:Invoice/cac:BillingReference/cac:InvoiceDocumentReference/cbc:ID",
        "BillingReferenceID",
    )?;
    let mut original = OriginalInvoiceRef::new(id);
    if let Some(uuid) = xpath_text_optional(
        ctx,
        "/ubl:Invoice/cac:BillingReference/cac:InvoiceDocumentReference/cbc:UUID",
    )? {
        original = original.with_uuid(uuid);
    }
    if let Some(issue_date) = xpath_text_optional(
        ctx,
        "/ubl:Invoice/cac:BillingReference/cac:InvoiceDocumentReference/cbc:IssueDate",
    )? {
        let date = NaiveDate::parse_from_str(&issue_date, "%Y-%m-%d").map_err(|e| {
            ParseError::InvalidValue {
                field: "BillingReferenceIssueDate",
                value: format!("{issue_date} ({e:?})"),
            }
        })?;
        original = original.with_issue_date(date);
    }
    Ok(original)
}

fn parse_seller(ctx: &xpath::Context) -> Result<Party<SellerRole>, ParseError> {
    let name = xpath_text_required(
        ctx,
        "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName",
        "SellerName",
    )?;
    let vat = xpath_text_required(
        ctx,
        "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID",
        "SellerVAT",
    )?;
    let crn = xpath_text_optional(
        ctx,
        "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyIdentification/cbc:ID",
    )?;
    let crn_scheme = xpath_text_optional(
        ctx,
        "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyIdentification/cbc:ID/@schemeID",
    )?;

    let address = parse_address(ctx)?;
    let other_id = match (crn, crn_scheme) {
        (Some(value), Some(scheme)) => Some(OtherId::with_scheme(value, scheme)),
        (Some(value), None) => Some(OtherId::new(value)),
        _ => None,
    };

    Party::<SellerRole>::new(name, address, vat, other_id)
        .map_err(|e| ParseError::XmlParse(format!("{e:?}")))
}

fn parse_address(ctx: &xpath::Context) -> Result<Address, ParseError> {
    let street = xpath_text_required(
        ctx,
        "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PostalAddress/cbc:StreetName",
        "SellerStreet",
    )?;
    let building_number = xpath_text_required(
        ctx,
        "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PostalAddress/cbc:BuildingNumber",
        "SellerBuildingNumber",
    )?;
    let city_subdivision = xpath_text_optional(
        ctx,
        "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PostalAddress/cbc:CitySubdivisionName",
    )?;
    let city = xpath_text_required(
        ctx,
        "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PostalAddress/cbc:CityName",
        "SellerCity",
    )?;
    let postal_code = xpath_text_required(
        ctx,
        "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PostalAddress/cbc:PostalZone",
        "SellerPostalCode",
    )?;
    let country = xpath_text_required(
        ctx,
        "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PostalAddress/cac:Country/cbc:IdentificationCode",
        "SellerCountry",
    )?;
    let country_code = CountryCode::for_alpha2(&country).map_err(|_| ParseError::InvalidValue {
        field: "SellerCountry",
        value: country,
    })?;

    Ok(Address {
        country_code,
        city,
        street,
        additional_street: None,
        building_number,
        additional_number: None,
        postal_code,
        subdivision: city_subdivision,
        district: None,
    })
}

fn parse_vat_category(ctx: &xpath::Context) -> Result<VatCategory, ParseError> {
    let category = xpath_text_required(
        ctx,
        "/ubl:Invoice/cac:InvoiceLine[1]/cac:Item/cac:ClassifiedTaxCategory/cbc:ID",
        "VatCategory",
    )?;
    match category.as_str() {
        "S" => Ok(VatCategory::Standard),
        "E" => Ok(VatCategory::Exempt),
        "Z" => Ok(VatCategory::Zero),
        "O" => Ok(VatCategory::OutOfScope),
        _ => Err(ParseError::InvalidValue {
            field: "VatCategory",
            value: category,
        }),
    }
}

fn parse_line_items(ctx: &xpath::Context) -> Result<Vec<LineItem>, ParseError> {
    let nodes = ctx
        .evaluate("//cac:InvoiceLine")
        .map_err(|e| ParseError::XPath(format!("{e:?}")))?
        .get_nodes_as_vec();
    if nodes.is_empty() {
        return Err(ParseError::MissingField("InvoiceLine"));
    }

    let mut items = Vec::with_capacity(nodes.len());
    for idx in 1..=nodes.len() {
        let base = format!("(//cac:InvoiceLine)[{idx}]");
        let _id = xpath_text_required(ctx, &format!("{base}/cbc:ID"), "LineID")?;
        let name = xpath_text_required(ctx, &format!("{base}/cac:Item/cbc:Name"), "LineName")?;
        let quantity = xpath_text_required(
            ctx,
            &format!("{base}/cbc:InvoicedQuantity"),
            "InvoicedQuantity",
        )?;
        let unit_code = xpath_text_required(
            ctx,
            &format!("{base}/cbc:InvoicedQuantity/@unitCode"),
            "InvoicedQuantity@unitCode",
        )?;
        let line_extension = xpath_text_required(
            ctx,
            &format!("{base}/cbc:LineExtensionAmount"),
            "LineExtensionAmount",
        )?;
        let price = xpath_text_required(
            ctx,
            &format!("{base}/cac:Price/cbc:PriceAmount"),
            "PriceAmount",
        )?;
        let vat_rate = xpath_text_required(
            ctx,
            &format!("{base}/cac:Item/cac:ClassifiedTaxCategory/cbc:Percent"),
            "LineVatPercent",
        )?;
        let vat_category = xpath_text_required(
            ctx,
            &format!("{base}/cac:Item/cac:ClassifiedTaxCategory/cbc:ID"),
            "LineVatCategory",
        )?;
        let vat_amount = xpath_text_required(
            ctx,
            &format!("{base}/cac:TaxTotal/cbc:TaxAmount"),
            "LineTaxAmount",
        )?;

        let vat_category = match vat_category.as_str() {
            "S" => VatCategory::Standard,
            "E" => VatCategory::Exempt,
            "Z" => VatCategory::Zero,
            "O" => VatCategory::OutOfScope,
            _ => {
                return Err(ParseError::InvalidValue {
                    field: "LineVatCategory",
                    value: vat_category,
                });
            }
        };

        let quantity = quantity
            .parse::<f64>()
            .map_err(|_| ParseError::InvalidValue {
                field: "InvoicedQuantity",
                value: quantity,
            })?;
        let unit_price = price.parse::<f64>().map_err(|_| ParseError::InvalidValue {
            field: "PriceAmount",
            value: price,
        })?;
        let total_amount = line_extension
            .parse::<f64>()
            .map_err(|_| ParseError::InvalidValue {
                field: "LineExtensionAmount",
                value: line_extension,
            })?;
        let vat_rate = vat_rate
            .parse::<f64>()
            .map_err(|_| ParseError::InvalidValue {
                field: "LineVatPercent",
                value: vat_rate,
            })?;
        let vat_amount = vat_amount
            .parse::<f64>()
            .map_err(|_| ParseError::InvalidValue {
                field: "LineTaxAmount",
                value: vat_amount,
            })?;

        let line_item = LineItem::try_from_parts(LineItemPartsFields {
            description: name,
            quantity,
            unit_code,
            unit_price,
            total_amount,
            vat_rate,
            vat_amount,
            vat_category,
        })
        .map_err(|err| ParseError::InvalidValue {
            field: "LineItem",
            value: err.to_string(),
        })?;

        items.push(line_item);
    }

    Ok(items)
}

fn parse_datetime(date: &str, time: &str) -> Result<chrono::DateTime<Utc>, ParseError> {
    let date =
        NaiveDate::parse_from_str(date, "%Y-%m-%d").map_err(|e| ParseError::InvalidValue {
            field: "IssueDate",
            value: format!("{date} ({e:?})"),
        })?;
    let time =
        NaiveTime::parse_from_str(time, "%H:%M:%S").map_err(|e| ParseError::InvalidValue {
            field: "IssueTime",
            value: format!("{time} ({e:?})"),
        })?;
    let naive = NaiveDateTime::new(date, time);
    Ok(Utc.from_utc_datetime(&naive))
}

fn build_context(doc: &Document) -> Result<xpath::Context, ParseError> {
    let ctx = xpath::Context::new(doc).map_err(|e| ParseError::XPath(format!("{e:?}")))?;
    ctx.register_namespace("ubl", INVOICE_NS)
        .map_err(|e| ParseError::XPath(format!("{e:?}")))?;
    ctx.register_namespace("cbc", CBC_NS)
        .map_err(|e| ParseError::XPath(format!("{e:?}")))?;
    ctx.register_namespace("cac", CAC_NS)
        .map_err(|e| ParseError::XPath(format!("{e:?}")))?;
    Ok(ctx)
}

fn xpath_text_required(
    ctx: &xpath::Context,
    expr: &str,
    label: &'static str,
) -> Result<String, ParseError> {
    xpath_text_optional(ctx, expr)?.ok_or(ParseError::MissingField(label))
}

fn xpath_text_optional(ctx: &xpath::Context, expr: &str) -> Result<Option<String>, ParseError> {
    let nodes = ctx
        .evaluate(expr)
        .map_err(|e| ParseError::XPath(format!("{e:?}")))?
        .get_nodes_as_vec();
    let node = match nodes.first() {
        Some(node) => node,
        None => return Ok(None),
    };
    let value = node.get_content().trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(value))
}

fn decode_qr_tlv(qr_b64: &str) -> Result<std::collections::HashMap<u8, Vec<u8>>, ParseError> {
    let raw = Base64::decode_vec(qr_b64).map_err(|e| ParseError::InvalidValue {
        field: "QR",
        value: format!("{e:?}"),
    })?;
    let mut entries = std::collections::HashMap::new();
    let mut idx = 0;
    while idx + 2 <= raw.len() {
        let tag = raw[idx];
        let len = raw[idx + 1] as usize;
        let start = idx + 2;
        let end = start + len;
        if end > raw.len() {
            return Err(ParseError::InvalidValue {
                field: "QR",
                value: "truncated TLV".to_string(),
            });
        }
        entries.insert(tag, raw[start..end].to_vec());
        idx = end;
    }
    Ok(entries)
}

#[allow(clippy::ptr_arg)]
fn bytes_to_string(bytes: &Vec<u8>) -> Option<String> {
    String::from_utf8(bytes.clone()).ok()
}
