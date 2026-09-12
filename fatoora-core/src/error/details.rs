//! Explicit binding schema: independent of Rust enum names and backend formats.
use super::{Diagnostic, DiagnosticSeverity, Error};
use crate::api::ZatcaError;
use crate::csr::CsrError;
use crate::invoice::sign::SigningError;
use crate::invoice::validation::XmlValidationError;
use crate::invoice::xml::{InvoiceXmlError, parse::ParseError};
use crate::invoice::{InvoiceError, InvoiceField, QrCodeError, ValidationKind};
use serde_json::{Value, json};

impl Error {
    /// Structured details for bindings, encoded as UTF-8 JSON.
    ///
    /// Every object has a `type` discriminator. Consumers must tolerate unknown
    /// types and additional fields. Decimal values are strings; item indices are
    /// zero-based. Messages are diagnostic text, not stable identifiers.
    /// See the error reference for the binding schema.
    pub fn details_json(&self) -> String {
        let details = match self {
            Self::Environment(crate::config::EnvironmentParseError::Invalid { input }) => {
                json!({"type": "invalid_environment", "value": input})
            }
            Self::Decimal(error) => decimal_details(error),
            Self::Csr(error) => error.details(),
            Self::Invoice(error) => error.details(),
            Self::Signing(error) => error.details(),
            Self::Qr(error) => error.details(),
            Self::Xml(error) => error.details(),
            Self::Parse(error) => error.details(),
            Self::XmlValidation(error) => error.details(),
            Self::Api(error) => error.details(),
        };
        details.to_string()
    }
}

impl InvoiceError {
    fn details(&self) -> Value {
        match self {
            Self::Validation(error) => json!({
                "type": "invoice_validation",
                "issues": error.issues().iter().map(|issue| json!({
                    "field": field_name(issue.field()),
                    "kind": validation_kind_name(issue.kind()),
                    "line_item_index": issue.line_item_index(),
                    "supplied": issue.supplied().map(|value| value.to_string()),
                    "expected": issue.expected().map(|value| value.to_string()),
                })).collect::<Vec<_>>()
            }),
            Self::Decimal(error) => decimal_details(error),
            Self::InvalidCountryCode(value) => {
                json!({"type": "invalid_country_code", "value": value})
            }
            Self::InvalidCurrencyCode(value) => {
                json!({"type": "invalid_currency_code", "value": value})
            }
            Self::InvalidTimestamp(value) => json!({"type": "invalid_timestamp", "value": value}),
            Self::InvalidIssueDate(value) => json!({"type": "invalid_issue_date", "value": value}),
            Self::MissingVatForSeller => json!({"type": "missing_seller_vat"}),
            Self::MissingBuyerId => json!({"type": "missing_buyer_id"}),
            Self::InvalidVatFormat => json!({"type": "invalid_vat_format"}),
        }
    }
}

impl XmlValidationError {
    fn details(&self) -> Value {
        match self {
            Self::SchemaParse { errors } => diagnostics("schema_parse", errors),
            Self::SchemaValidation { errors } => diagnostics("schema_validation", errors),
            Self::InvalidXsdPath { path } => json!({"type": "invalid_xsd_path", "path": path}),
            Self::XmlParse { message } => message_details("xml_parse", message),
        }
    }
}

impl InvoiceXmlError {
    fn details(&self) -> Value {
        match self {
            Self::Serialize { source } => {
                diagnostics("xml_serialize", std::slice::from_ref(source))
            }
        }
    }
}

impl SigningError {
    fn details(&self) -> Value {
        match self {
            Self::SigningError(message) => message_details("signing", message),
            Self::Xml(source) => diagnostics("signing_xml", std::slice::from_ref(source)),
            Self::InvalidInput(source) => {
                diagnostics("signing_input", std::slice::from_ref(source))
            }
            Self::Serialize(error) => error.details(),
            Self::Invoice(error) => error.details(),
            Self::Qr(error) => error.details(),
        }
    }
}

impl ParseError {
    fn details(&self) -> Value {
        match self {
            Self::Qr(error) => error.details(),
            Self::Invoice(error) => error.details(),
            Self::Decimal(error) => decimal_details(error),
            Self::Io { path, source } => {
                json!({"type": "io", "path": path.to_string_lossy(), "diagnostics": [{"message": source.to_string()}]})
            }
            Self::MissingField(field) => json!({"type": "missing_field", "field": field}),
            Self::InvalidValue { field, value } => {
                json!({"type": "invalid_value", "field": field, "value": value})
            }
            Self::XmlParse(message) => message_details("xml_parse", message),
            Self::XPath(message) => message_details("xpath", message),
        }
    }
}

impl CsrError {
    fn details(&self) -> Value {
        match self {
            Self::MissingProperty { path, key } => {
                json!({"type": "missing_property", "path": path.to_string_lossy(), "key": key})
            }
            Self::PropertiesRead { path, source } => {
                json!({"type": "properties_parse", "path": path.to_string_lossy(), "diagnostics": [diagnostic_json(source)]})
            }
            Self::Io { path, source } => {
                json!({"type": "io", "path": path.to_string_lossy(), "diagnostics": [{"message": source.to_string()}]})
            }
            Self::DerEncode { context, source } => {
                json!({"type": "der_encode", "context": context, "diagnostics": [diagnostic_json(source)]})
            }
            Self::AddExtension { which, message } => {
                json!({"type": "csr_extension", "extension": which, "diagnostics": [{"message": message}]})
            }
            Self::InvalidSubject { message } => message_details("invalid_subject", message),
            Self::InvalidSan { message } => message_details("invalid_san", message),
            Self::RequestBuild { message } => message_details("csr_request", message),
            Self::CsrBuild { message } => message_details("csr_build", message),
            Self::KeyDecode { message } => message_details("key_decode", message),
            Self::KeyEncode { message } => message_details("key_encode", message),
            Self::Validation { message } => message_details("csr_validation", message),
        }
    }
}

impl QrCodeError {
    fn details(&self) -> Value {
        match self {
            Self::ValueTooLong { tag, len } => {
                json!({"type": "qr_value_too_long", "tag": tag, "length": len, "limit": 255})
            }
            Self::EncodedTooLong { len } => {
                json!({"type": "qr_encoded_too_long", "length": len, "limit": 700})
            }
            Self::MissingSellerName => json!({"type": "missing_seller_name"}),
            Self::MissingSellerVat => json!({"type": "missing_seller_vat"}),
            Self::Xml(message) => message_details("qr_xml", message),
        }
    }
}

impl ZatcaError {
    fn details(&self) -> Value {
        match self {
            Self::Unauthorized(response) => json!({"type": "api_unauthorized", "response": {
                "timestamp": response.timestamp(), "status": response.status(), "error": response.error(), "message": response.message()
            }}),
            Self::ServerError(response) => json!({"type": "api_server", "response": {
                "category": response.category(), "code": response.code(), "message": response.message()
            }}),
            Self::NetworkError(message) => message_details("network", message),
            Self::InvalidResponse(message) => message_details("invalid_response", message),
            Self::Http(message) => message_details("http", message),
            Self::ClientState(message) => message_details("client_state", message),
        }
    }
}

fn decimal_details(error: &crate::DecimalError) -> Value {
    match error {
        crate::DecimalError::InvalidSyntax => json!({"type": "invalid_decimal"}),
        crate::DecimalError::OutOfRange => json!({"type": "decimal_out_of_range"}),
    }
}

fn diagnostics(kind: &str, values: &[Diagnostic]) -> Value {
    json!({"type": kind, "diagnostics": values.iter().map(diagnostic_json).collect::<Vec<_>>()})
}

fn message_details(kind: &str, message: &str) -> Value {
    json!({"type": kind, "diagnostics": [{"message": message}]})
}

fn diagnostic_json(diagnostic: &Diagnostic) -> Value {
    let severity = diagnostic.severity().map(|severity| match severity {
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
        DiagnosticSeverity::Fatal => "fatal",
    });
    json!({"message": diagnostic.message(), "file": diagnostic.file(), "line": diagnostic.line(), "column": diagnostic.column(), "severity": severity})
}

fn field_name(value: InvoiceField) -> &'static str {
    match value {
        InvoiceField::Id => "id",
        InvoiceField::Uuid => "uuid",
        InvoiceField::IssueDateTime => "issue_date_time",
        InvoiceField::Currency => "currency",
        InvoiceField::PreviousInvoiceHash => "previous_invoice_hash",
        InvoiceField::InvoiceCounter => "invoice_counter",
        InvoiceField::Seller => "seller",
        InvoiceField::LineItems => "line_items",
        InvoiceField::PaymentMeansCode => "payment_means_code",
        InvoiceField::VatCategory => "vat_category",
        InvoiceField::LineItemDescription => "line_item_description",
        InvoiceField::LineItemUnitCode => "line_item_unit_code",
        InvoiceField::LineItemQuantity => "line_item_quantity",
        InvoiceField::LineItemUnitPrice => "line_item_unit_price",
        InvoiceField::LineItemTotalAmount => "line_item_total_amount",
        InvoiceField::LineItemVatRate => "line_item_vat_rate",
        InvoiceField::LineItemVatAmount => "line_item_vat_amount",
        InvoiceField::InvoiceLevelDiscount => "invoice_level_discount",
        InvoiceField::InvoiceLevelCharge => "invoice_level_charge",
    }
}

fn validation_kind_name(value: ValidationKind) -> &'static str {
    match value {
        ValidationKind::Missing => "missing",
        ValidationKind::Empty => "empty",
        ValidationKind::InvalidFormat => "invalid_format",
        ValidationKind::OutOfRange => "out_of_range",
        ValidationKind::Mismatch => "mismatch",
    }
}
