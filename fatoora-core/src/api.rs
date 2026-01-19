//! ZATCA HTTP API client and response types.
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x509_cert::request::CertReq;

use crate::{
    config::{Config, EnvironmentType},
    csr::ToBase64String,
    invoice::SignedInvoice,
};
use std::marker::PhantomData;

/// Errors returned by the ZATCA API client.
#[derive(Error, Debug)]
pub enum ZatcaError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Invalid response from ZATCA: {0}")]
    InvalidResponse(String),
    #[error("Unauthorized: {0:?}")]
    Unauthorized(UnauthorizedResponse),
    #[error("Server error: {0:?}")]
    ServerError(ServerErrorResponse),
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Client state error: {0}")]
    ClientState(String),
}

/// Marker trait for API token scope, either Compliance (CCSID) or Production (PCSID).
pub trait TokenScope {}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
/// Compliance (CCSID) token scope.
pub struct Compliance;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
/// Production (PCSID) token scope.
pub struct Production;
impl TokenScope for Compliance {}
impl TokenScope for Production {}

/// ZATCA API client.
///
/// # Examples
/// ```rust,no_run
/// use fatoora_core::api::ZatcaClient;
/// use fatoora_core::config::Config;
///
/// let client = ZatcaClient::new(Config::default())?;
/// # let _ = client;
/// use fatoora_core::api::ZatcaError;
/// # Ok::<(), ZatcaError>(())
/// ```
#[derive(Debug)]
pub struct ZatcaClient {
    config: Config,
    _client: Client,
    base_url: String,
}

/// API validation response.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidationResponse {
    #[serde(rename = "validationResults")]
    validation_results: ValidationResults,
    #[serde(rename = "reportingStatus")]
    reporting_status: Option<String>,
    #[serde(rename = "clearanceStatus")]
    clearance_status: Option<String>,
    #[serde(rename = "qrSellertStatus")]
    qr_seller_status: Option<String>,
    #[serde(rename = "qrBuyertStatus")]
    qr_buyer_status: Option<String>,
}

impl ValidationResponse {
    pub fn validation_results(&self) -> &ValidationResults {
        &self.validation_results
    }

    pub fn reporting_status(&self) -> Option<&str> {
        self.reporting_status.as_deref()
    }

    pub fn clearance_status(&self) -> Option<&str> {
        self.clearance_status.as_deref()
    }

    pub fn qr_seller_status(&self) -> Option<&str> {
        self.qr_seller_status.as_deref()
    }

    pub fn qr_buyer_status(&self) -> Option<&str> {
        self.qr_buyer_status.as_deref()
    }
}

/// Validation results container.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidationResults {
    #[serde(rename = "infoMessages", default)]
    info_messages: MessageList,
    #[serde(rename = "warningMessages", default)]
    warning_messages: Vec<ValidationMessage>,
    #[serde(rename = "errorMessages", default)]
    error_messages: Vec<ValidationMessage>,
    #[serde(default)]
    status: Option<String>,
}

impl ValidationResults {
    pub fn info_messages(&self) -> &MessageList {
        &self.info_messages
    }

    pub fn warning_messages(&self) -> &[ValidationMessage] {
        &self.warning_messages
    }

    pub fn error_messages(&self) -> &[ValidationMessage] {
        &self.error_messages
    }

    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }
}

/// Validation message.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidationMessage {
    #[serde(rename = "type")]
    message_type: Option<String>,
    code: Option<String>,
    category: Option<String>,
    message: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

impl ValidationMessage {
    pub fn message_type(&self) -> Option<&str> {
        self.message_type.as_deref()
    }

    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
#[derive(Default)]
/// Message list returned by the API.
pub enum MessageList {
    One(ValidationMessage),
    Many(Vec<ValidationMessage>),
    #[default]
    Empty,
}

/// Unauthorized response body.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnauthorizedResponse {
    timestamp: Option<i64>,
    status: Option<u16>,
    error: Option<String>,
    message: Option<String>,
}

impl UnauthorizedResponse {
    pub fn timestamp(&self) -> Option<i64> {
        self.timestamp
    }

    pub fn status(&self) -> Option<u16> {
        self.status
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

/// Server error response body.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerErrorResponse {
    category: Option<String>,
    code: Option<String>,
    message: Option<String>,
}

impl ServerErrorResponse {
    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}


/// CSID credentials used for API calls.
/// This is usually obtained after requesting a CSID from ZATCA.
/// ie. through [post_ccsid_for_pcsid][ZatcaClient::post_ccsid_for_pcsid] or [post_csr_for_ccsid][ZatcaClient::post_csr_for_ccsid].
/// But can also be constructed manually if you have the necessary values.
///
/// # Examples
/// ```rust
/// use fatoora_core::api::{CsidCredentials, Compliance};
/// use fatoora_core::config::EnvironmentType;
///
/// let creds = CsidCredentials::<Compliance>::new(
///     EnvironmentType::NonProduction,
///     Some(1234567890123),             // requestID field
///     "TUlJQ1BUQ0NBZU9nQXdJQkFnS....", // binarySecurityToken field
///     "Dehvg1fc8GF6Jwt5bOxXwC6en....", // secret field 
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CsidCredentials<T> {
    env: EnvironmentType,
    request_id: Option<u64>,
    binary_security_token: String,
    secret: String,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> CsidCredentials<T> {
    /// Create credential bundle for ZATCA requests.
    pub fn new(
        env: EnvironmentType,
        request_id: Option<u64>,
        binary_security_token: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        Self {
            env,
            request_id,
            binary_security_token: binary_security_token.into(),
            secret: secret.into(),
            _marker: PhantomData,
        }
    }

    pub fn env(&self) -> EnvironmentType {
        self.env
    }

    pub fn request_id(&self) -> Option<u64> {
        self.request_id
    }

    pub fn binary_security_token(&self) -> &str {
        &self.binary_security_token
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }
}

#[derive(Debug, Deserialize)]
struct CsidResponseBody {
    #[serde(rename = "requestID")]
    request_id: Option<u64>,
    #[serde(rename = "binarySecurityToken")]
    binary_security_token: String,
    secret: String,
    #[allow(dead_code)]
    #[serde(rename = "tokenType")]
    token_type: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "dispositionMessage")]
    disposition_message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RenewalResponseBody {
    Direct(CsidResponseBody),
    Wrapped { value: CsidResponseBody },
}

// Public API
impl ZatcaClient {
    /// Create a new API client using the provided configuration.
    ///
    /// # Errors
    /// Returns [`ZatcaError::Http`] if the HTTP client cannot be built.
    pub fn new(config: Config) -> Result<Self, ZatcaError> {
        let client = Client::builder().build().map_err(ZatcaError::Http)?;
        let base_url = std::env::var("FATOORA_ZATCA_BASE_URL")
            .ok()
            .map(|value| {
                if value.ends_with('/') {
                    value
                } else {
                    format!("{value}/")
                }
            })
            .unwrap_or_else(|| config.env().endpoint_url().to_string());

        Ok(Self {
            config,
            _client: client,
            base_url,
        })
    }

    /// Report a simplified invoice to ZATCA's gateway.
    /// See [ZATCA documentation](https://sandbox.zatca.gov.sa/IntegrationSandbox/reporting-api) for more details.
    ///
    /// # Errors
    /// Returns [`ZatcaError`] for network failures, invalid responses, or client state issues.
    pub async fn report_simplified_invoice(
        &self,
        invoice: &SignedInvoice,
        credentials: &CsidCredentials<Production>,
        clearance_status: bool,
        accept_language: Option<&str>,
    ) -> Result<ValidationResponse, ZatcaError> {
        self.ensure_env(credentials)?;
        if !invoice.data().invoice_type().is_simplified() {
            return Err(ZatcaError::ClientState(
                "Reporting only supports simplified invoices".into(),
            ));
        }

        let payload = serde_json::json!({
            "invoiceHash": invoice.invoice_hash(),
            "uuid": invoice.uuid(),
            "invoice": invoice.to_xml_base64()
        });
        let url = self.build_endpoint("invoices/reporting/single");
        let mut request = self
            ._client
            .post(url)
            .header("Accept", "application/json")
            .header("Accept-Version", "V2")
            .header("Content-Type", "application/json")
            .header("Clearance-Status", if clearance_status { "1" } else { "0" })
            .basic_auth(
                credentials.binary_security_token().to_string(),
                Some(credentials.secret().to_string()),
            )
            .json(&payload);

        match accept_language {
            Some("ar") => request = request.header("accept-language", "ar"),
            _ => request = request.header("accept-language", "en")
        }

        let response = request.send().await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.is_success() || status.as_u16() == 400 || status.as_u16() == 409 {
            match serde_json::from_str::<ValidationResponse>(&body) {
                Ok(parsed) => return Ok(parsed),
                Err(_) => {
                    return Err(ZatcaError::InvalidResponse(format!(
                        "status {status}: {body}"
                    )))
                }
            }
        }

        if status.as_u16() == 406 {
            return Err(ZatcaError::InvalidResponse(format!(
                "status {status}: {body}"
            )));
        }

        if status.as_u16() == 401 {
            let parsed = serde_json::from_str::<UnauthorizedResponse>(&body).unwrap_or_else(|_| {
                UnauthorizedResponse {
                    timestamp: None,
                    status: Some(401),
                    error: Some("Unauthorized".into()),
                    message: Some(body.clone()),
                }
            });
            return Err(ZatcaError::Unauthorized(parsed));
        }

        if status.is_server_error() {
            let parsed = serde_json::from_str::<ServerErrorResponse>(&body).unwrap_or_else(|_| {
                ServerErrorResponse {
                    category: None,
                    code: Some("ServerError".into()),
                    message: Some(body.clone()),
                }
            });
            return Err(ZatcaError::ServerError(parsed));
        }

        Err(ZatcaError::InvalidResponse(format!(
            "status {status}: {body}"
        )))
    }

    /// Clear a standard invoice through ZATCA's gateway.
    /// See [ZATCA documentation](https://sandbox.zatca.gov.sa/Integration/clearance-api) for more details.
    ///
    /// # Errors
    /// Returns [`ZatcaError`] for network failures, invalid responses, or client state issues.
    pub async fn clear_standard_invoice(
        &self,
        invoice: &SignedInvoice,
        credentials: &CsidCredentials<Production>,
        clearance_status: bool,
        accept_language: Option<&str>,
    ) -> Result<ValidationResponse, ZatcaError> {
        self.ensure_env(credentials)?;
        if invoice.data().invoice_type().is_simplified() {
            return Err(ZatcaError::ClientState(
                "Clearance only supports standard invoices".into(),
            ));
        }

        let payload = serde_json::json!({
            "invoiceHash": invoice.invoice_hash(),
            "uuid": invoice.uuid(),
            "invoice": invoice.to_xml_base64()
        });
        let url = self.build_endpoint("invoices/clearance/single");
        let mut request = self
            ._client
            .post(url)
            .header("Accept", "application/json")
            .header("Accept-Version", "V2")
            .header("Content-Type", "application/json")
            .header("Clearance-Status", if clearance_status { "1" } else { "0" })
            .basic_auth(
                credentials.binary_security_token().to_string(),
                Some(credentials.secret().to_string()),
            )
            .json(&payload);

        match accept_language {
            Some("ar") => request = request.header("accept-language", "ar"),
            _ => request = request.header("accept-language", "en"),
        }

        let response = request.send().await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.is_success() || status.as_u16() == 400 {
            match serde_json::from_str::<ValidationResponse>(&body) {
                Ok(parsed) => return Ok(parsed),
                Err(_) => {
                    return Err(ZatcaError::InvalidResponse(format!(
                        "status {status}: {body}"
                    )))
                }
            }
        }

        if status.as_u16() == 401 {
            let parsed = serde_json::from_str::<UnauthorizedResponse>(&body).unwrap_or_else(|_| {
                UnauthorizedResponse {
                    timestamp: None,
                    status: Some(401),
                    error: Some("Unauthorized".into()),
                    message: Some(body.clone()),
                }
            });
            return Err(ZatcaError::Unauthorized(parsed));
        }

        if status.is_server_error() {
            let parsed = serde_json::from_str::<ServerErrorResponse>(&body).unwrap_or_else(|_| {
                ServerErrorResponse {
                    category: None,
                    code: Some("ServerError".into()),
                    message: Some(body.clone()),
                }
            });
            return Err(ZatcaError::ServerError(parsed));
        }

        Err(ZatcaError::InvalidResponse(format!(
            "status {status}: {body}"
        )))
    }

    /// Check invoice compliance through ZATCA's gateway.
    /// See [ZATCA documentation](https://sandbox.zatca.gov.sa/IntegrationSandbox/preInvoice-api) for more details.
    ///
    /// # Errors
    /// Returns [`ZatcaError`] for network failures, invalid responses, or client state issues.
    pub async fn check_invoice_compliance(
        &self,
        invoice: &SignedInvoice,
        credentials: &CsidCredentials<Compliance>,
    ) -> Result<ValidationResponse, ZatcaError> {
        self.ensure_env(credentials)?;
        let payload = serde_json::json!({
            "invoiceHash": invoice.invoice_hash(),
            "uuid": invoice.uuid(),
            "invoice": invoice.to_xml_base64()
        });

        let url = self.build_endpoint("compliance/invoices");

        let response = self
            ._client
            .post(url)
            .header("Accept", "application/json")
            .header("Accept-Language", "en")
            .header("Accept-Version", "V2")
            .header("Content-Type", "application/json")
            .basic_auth(
                credentials.binary_security_token().to_string(),
                Some(credentials.secret().to_string()),
            )
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.is_success() || status.as_u16() == 400 {
            let parsed = serde_json::from_str::<ValidationResponse>(&body)
                .map_err(|e| ZatcaError::InvalidResponse(format!("Invalid response: {e:?}")))?;
            return Ok(parsed);
        }

        if status.as_u16() == 401 {
            let parsed = serde_json::from_str::<UnauthorizedResponse>(&body).unwrap_or_else(|_| {
                UnauthorizedResponse {
                    timestamp: None,
                    status: Some(401),
                    error: Some("Unauthorized".into()),
                    message: Some(body.clone()),
                }
            });
            return Err(ZatcaError::Unauthorized(parsed));
        }

        if status.is_server_error() {
            let parsed = serde_json::from_str::<ServerErrorResponse>(&body).unwrap_or_else(|_| {
                ServerErrorResponse {
                    category: None,
                    code: Some("ServerError".into()),
                    message: Some(body.clone()),
                }
            });
            return Err(ZatcaError::ServerError(parsed));
        }

        Err(ZatcaError::InvalidResponse(format!(
            "status {status}: {body}"
        )))
    }
    /// Request a compliance CSID from ZATCA by submitting a CSR.
    /// See [ZATCA
    /// documentation](https://sandbox.zatca.gov.sa/IntegrationSandbox/complianceCert-api) for more details.
    ///
    /// # Errors
    /// Returns [`ZatcaError`] if the request fails or the response cannot be parsed.
    pub async fn post_csr_for_ccsid(
        &self,
        csr: &CertReq,
        otp: &str,
    ) -> Result<CsidCredentials<Compliance>, ZatcaError> {
        let encoded_csr = csr
            .to_pem_base64_string()
            .map_err(|e| ZatcaError::InvalidResponse(e.to_string()))?;
        let csr_payload = serde_json::json!({ "csr": encoded_csr });
        let url = self.build_endpoint("compliance");
        let response = self
            ._client
            .post(url)
            .header("Accept", "application/json")
            .header("OTP", otp)
            .header("Accept-Version", "V2")
            .header("Content-Type", "application/json")
            .json(&csr_payload)
            .send()
            .await?;
        let status = response.status();

        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            return Err(ZatcaError::InvalidResponse(format!(
                "status {status}: {message}"
            )));
        }

        let payload: CsidResponseBody = response
            .json()
            .await
            .map_err(|e| ZatcaError::InvalidResponse(e.to_string()))?;
        Ok(CsidCredentials::new(
            self.config.env(),
            payload.request_id,
            payload.binary_security_token,
            payload.secret,
        ))
    }

    /// Requests a production CSID from ZATCA using a compliance CSID previously obtained e.g. from [post_csr_for_ccsid][ZatcaClient::post_csr_for_ccsid].
    /// See [ZATCA documentation](https://sandbox.zatca.gov.sa/Integration/request-api) for more details.
    ///
    /// # Errors
    /// Returns [`ZatcaError`] if the request fails or the compliance CSID is missing data.
    pub async fn post_ccsid_for_pcsid(
        &self,
        ccsid: &CsidCredentials<Compliance>,
    ) -> Result<CsidCredentials<Production>, ZatcaError> {
        self.ensure_env(ccsid)?;
        let request_id = ccsid
            .request_id()
            .ok_or_else(|| ZatcaError::ClientState("Missing compliance request_id".into()))?;
        let payload = serde_json::json!({
            "compliance_request_id": request_id,
        });

        let url = self.build_endpoint("production/csids");
        let response = self
            ._client
            .post(url)
            .header("Accept", "application/json")
            .header("Accept-Version", "V2")
            .header("Content-Type", "application/json")
            .basic_auth(
                ccsid.binary_security_token().to_string(),
                Some(ccsid.secret().to_string()),
            )
            .json(&payload)
            .send()
            .await?;
        let status = response.status();

        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            return Err(ZatcaError::InvalidResponse(format!(
                "status {status}: {message}"
            )));
        }

        let payload: CsidResponseBody = response
            .json()
            .await
            .map_err(|e| ZatcaError::InvalidResponse(e.to_string()))?;

        Ok(CsidCredentials::new(
            self.config.env(),
            payload.request_id,
            payload.binary_security_token,
            payload.secret,
        ))
    }

    /// Renew a production CSID by submitting a new CSR.
    /// See [ZATCA documentation](https://sandbox.zatca.gov.sa/Integration/renewal-api) for more details.
    ///
    /// # Errors
    /// Returns [`ZatcaError`] if the request fails or the response cannot be parsed.
    pub async fn renew_csid(
        &self,
        pcsid: &CsidCredentials<Production>,
        csr: &CertReq,
        otp: &str,
        accept_language: Option<&str>,
    ) -> Result<CsidCredentials<Production>, ZatcaError> {
        self.ensure_env(pcsid)?;
        let encoded_csr = csr
            .to_pem_base64_string()
            .map_err(|e| ZatcaError::InvalidResponse(e.to_string()))?;
        let csr_payload = serde_json::json!({ "csr": encoded_csr });
        let url = self.build_endpoint("production/csids");
        let mut request = self
            ._client
            .patch(url)
            .header("Accept", "application/json")
            .header("OTP", otp)
            .header("Accept-Version", "V2")
            .header("Content-Type", "application/json")
            .basic_auth(
                pcsid.binary_security_token().to_string(),
                Some(pcsid.secret().to_string()),
            )
            .json(&csr_payload);

        match accept_language {
            Some("ar") => request = request.header("accept-language", "ar"),
            _ => request = request.header("accept-language", "en"),
        }

        let response = request.send().await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.is_success() || status.as_u16() == 428 {
            let parsed: RenewalResponseBody = serde_json::from_str(&body)
                .map_err(|e| ZatcaError::InvalidResponse(format!("Invalid response: {e:?}")))?;
            let payload = match parsed {
                RenewalResponseBody::Direct(value) => value,
                RenewalResponseBody::Wrapped { value } => value,
            };
            return Ok(CsidCredentials::new(
                self.config.env(),
                payload.request_id,
                payload.binary_security_token,
                payload.secret,
            ));
        }

        if status.as_u16() == 401 {
            let parsed = serde_json::from_str::<UnauthorizedResponse>(&body).unwrap_or_else(|_| {
                UnauthorizedResponse {
                    timestamp: None,
                    status: Some(401),
                    error: Some("Unauthorized".into()),
                    message: Some(body.clone()),
                }
            });
            return Err(ZatcaError::Unauthorized(parsed));
        }

        if status.is_server_error() {
            let parsed = serde_json::from_str::<ServerErrorResponse>(&body).unwrap_or_else(|_| {
                ServerErrorResponse {
                    category: None,
                    code: Some("ServerError".into()),
                    message: Some(body.clone()),
                }
            });
            return Err(ZatcaError::ServerError(parsed));
        }

        Err(ZatcaError::InvalidResponse(format!(
            "status {status}: {body}"
        )))
    }
}

// Private API
impl ZatcaClient {
    fn build_endpoint(&self, path: &str) -> String {
        format!(
            "{}{}",
            self.base_url,
            path.trim_start_matches('/')
        )
    }

    fn ensure_env<T>(&self, creds: &CsidCredentials<T>) -> Result<(), ZatcaError> {
        if creds.env() != self.config.env() {
            return Err(ZatcaError::ClientState("CSID environment mismatch".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        csr::CsrProperties,
        invoice::{
            sign::SignedProperties, xml::ToXml, Address, InvoiceBuilder, InvoiceSubType,
            InvoiceType, LineItem, Party, RequiredInvoiceFields, SellerRole, VatCategory,
        },
    };
    use base64ct::{Base64, Encoding};
    use chrono::TimeZone;
    use httpmock::{Method::PATCH, Method::POST, MockServer};
    use isocountry::CountryCode;
    use iso_currency::Currency;
    use std::path::Path;

    #[test]
    fn deserialize_validation_response_with_info_object() {
        let payload = r#"{
          "validationResults": {
            "infoMessages": {
              "type": "INFO",
              "code": "XSD_ZATCA_VALID",
              "category": "XSD validation",
              "message": "Complied with UBL 2.1 standards in line with ZATCA specifications",
              "status": "PASS"
            }
          },
          "warningMessages": [],
          "errorMessages": [],
          "status": "PASS",
          "reportingStatus": "REPORTED",
          "clearanceStatus": null,
          "qrSellertStatus": null,
          "qrBuyertStatus": null
        }"#;

        let parsed: ValidationResponse = serde_json::from_str(payload).expect("deserialize");
        match parsed.validation_results.info_messages {
            MessageList::One(msg) => assert_eq!(msg.code.as_deref(), Some("XSD_ZATCA_VALID")),
            other => panic!("expected single info message, got {:?}", other),
        }
    }

    #[test]
    fn deserialize_validation_response_with_info_array() {
        let payload = r#"{
          "validationResults": {
            "infoMessages": [
              {
                "type": "INFO",
                "code": "XSD_ZATCA_VALID",
                "category": "XSD validation",
                "message": "Complied with UBL 2.1 standards in line with ZATCA specifications",
                "status": "PASS"
              }
            ],
            "warningMessages": [],
            "errorMessages": [
              {
                "type": "ERROR",
                "code": "BR-KSA-37",
                "category": "KSA",
                "message": "The seller address building number must contain 4 digits.",
                "status": "ERROR"
              }
            ],
            "status": "ERROR"
          },
          "reportingStatus": "NOT_REPORTED",
          "clearanceStatus": null,
          "qrSellertStatus": null,
          "qrBuyertStatus": null
        }"#;

        let parsed: ValidationResponse = serde_json::from_str(payload).expect("deserialize");
        match parsed.validation_results.info_messages {
            MessageList::Many(list) => assert_eq!(list.len(), 1),
            other => panic!("expected info list, got {:?}", other),
        }
        assert_eq!(parsed.validation_results.error_messages.len(), 1);
    }

    #[test]
    fn deserialize_renewal_response_wrapped() {
        let payload = r#"{
          "value": {
            "requestID": 1234567890,
            "tokenType": null,
            "dispositionMessage": "NOT_COMPLIANT",
            "binarySecurityToken": "token",
            "secret": "secret",
            "errors": null
          }
        }"#;

        let parsed: RenewalResponseBody = serde_json::from_str(payload).expect("deserialize");
        let value = match parsed {
            RenewalResponseBody::Wrapped { value } => value,
            RenewalResponseBody::Direct(value) => value,
        };
        assert_eq!(value.request_id, Some(1234567890));
        assert_eq!(value.binary_security_token, "token");
        assert_eq!(value.secret, "secret");
    }

    #[test]
    fn deserialize_validation_response_defaults_info_messages() {
        let payload = r#"{
          "validationResults": {
            "warningMessages": [],
            "errorMessages": [],
            "status": "PASS"
          },
          "reportingStatus": "REPORTED",
          "clearanceStatus": null,
          "qrSellertStatus": null,
          "qrBuyertStatus": null
        }"#;

        let parsed: ValidationResponse = serde_json::from_str(payload).expect("deserialize");
        assert!(matches!(
            parsed.validation_results.info_messages,
            MessageList::Empty
        ));
    }

    #[test]
    fn csid_credentials_new_stores_env() {
        let creds = CsidCredentials::<Compliance>::new(
            EnvironmentType::Simulation,
            Some(10),
            "token",
            "secret",
        );
        assert_eq!(creds.env(), EnvironmentType::Simulation);
        assert_eq!(creds.request_id, Some(10));
    }

    #[test]
    fn response_getters_expose_fields() {
        let payload = r#"{
          "validationResults": {
            "infoMessages": {
              "type": "INFO",
              "code": "INFO_CODE",
              "category": "Info",
              "message": "ok",
              "status": "PASS"
            },
            "warningMessages": [
              {
                "type": "WARN",
                "code": "WARN_CODE",
                "category": "Warn",
                "message": "warn",
                "status": "WARN"
              }
            ],
            "errorMessages": [],
            "status": "PASS"
          },
          "reportingStatus": "REPORTED",
          "clearanceStatus": "CLEARED",
          "qrSellertStatus": "OK",
          "qrBuyertStatus": "OK"
        }"#;

        let parsed: ValidationResponse = serde_json::from_str(payload).expect("deserialize");
        assert_eq!(parsed.reporting_status(), Some("REPORTED"));
        assert_eq!(parsed.clearance_status(), Some("CLEARED"));
        assert_eq!(parsed.qr_seller_status(), Some("OK"));
        assert_eq!(parsed.qr_buyer_status(), Some("OK"));

        let results = parsed.validation_results();
        assert_eq!(results.status(), Some("PASS"));
        assert_eq!(results.warning_messages().len(), 1);
        assert_eq!(results.error_messages().len(), 0);

        match results.info_messages() {
            MessageList::One(message) => {
                assert_eq!(message.message_type(), Some("INFO"));
                assert_eq!(message.code(), Some("INFO_CODE"));
                assert_eq!(message.category(), Some("Info"));
                assert_eq!(message.message(), Some("ok"));
                assert_eq!(message.status(), Some("PASS"));
            }
            _ => panic!("expected info message"),
        }
    }

    #[test]
    fn error_response_getters_expose_fields() {
        let unauthorized = UnauthorizedResponse {
            timestamp: Some(1),
            status: Some(401),
            error: Some("Unauthorized".into()),
            message: Some("nope".into()),
        };
        assert_eq!(unauthorized.timestamp(), Some(1));
        assert_eq!(unauthorized.status(), Some(401));
        assert_eq!(unauthorized.error(), Some("Unauthorized"));
        assert_eq!(unauthorized.message(), Some("nope"));

        let server_error = ServerErrorResponse {
            category: Some("Server".into()),
            code: Some("ERR".into()),
            message: Some("boom".into()),
        };
        assert_eq!(server_error.category(), Some("Server"));
        assert_eq!(server_error.code(), Some("ERR"));
        assert_eq!(server_error.message(), Some("boom"));
    }

    #[test]
    fn build_endpoint_trims_leading_slash() {
        let client = ZatcaClient::new(Config::default()).expect("client");
        let with_slash = client.build_endpoint("/invoices/reporting/single");
        let without_slash = client.build_endpoint("invoices/reporting/single");
        assert_eq!(with_slash, without_slash);
    }

    #[test]
    fn ensure_env_rejects_mismatch() {
        let client = ZatcaClient::new(Config::default()).expect("client");
        let creds = CsidCredentials::<Compliance>::new(
            EnvironmentType::Production,
            None,
            "token",
            "secret",
        );
        let err = client.ensure_env(&creds).expect_err("env mismatch");
        assert!(matches!(err, ZatcaError::ClientState(_)));
    }

    #[tokio::test]
    async fn report_rejects_standard_invoice() {
        let signed_invoice = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Standard));

        let creds = CsidCredentials::new(
            EnvironmentType::NonProduction,
            None,
            "token",
            "secret",
        );
        let client = ZatcaClient::new(Config::default()).expect("client");

        let result = client
            .report_simplified_invoice(&signed_invoice, &creds, false, None)
            .await;
        assert!(matches!(result, Err(ZatcaError::ClientState(_))));
    }

    #[tokio::test]
    async fn clearance_rejects_simplified_invoice() {
        let signed_invoice = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Simplified));

        let creds = CsidCredentials::new(
            EnvironmentType::NonProduction,
            None,
            "token",
            "secret",
        );
        let client = ZatcaClient::new(Config::default()).expect("client");

        let result = client
            .clear_standard_invoice(&signed_invoice, &creds, true, None)
            .await;
        assert!(matches!(result, Err(ZatcaError::ClientState(_))));
    }

    #[tokio::test]
    async fn compliance_rejects_env_mismatch() {
        let signed_invoice = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Simplified));
        let client = ZatcaClient::new(Config::default()).expect("client");
        let creds = CsidCredentials::new(
            EnvironmentType::Production,
            None,
            "token",
            "secret",
        );

        let result = client.check_invoice_compliance(&signed_invoice, &creds).await;
        assert!(matches!(result, Err(ZatcaError::ClientState(_))));
    }

    #[tokio::test]
    async fn post_ccsid_requires_request_id() {
        let client = ZatcaClient::new(Config::default()).expect("client");
        let creds = CsidCredentials::new(
            EnvironmentType::NonProduction,
            None,
            "token",
            "secret",
        );

        let result = client.post_ccsid_for_pcsid(&creds).await;
        assert!(matches!(result, Err(ZatcaError::ClientState(_))));
    }

    use std::sync::{Mutex, OnceLock};

    fn base_url_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct BaseUrlGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        previous: Option<String>,
    }

    impl BaseUrlGuard {
        fn new(url: &str) -> Self {
            let lock = base_url_lock().lock().expect("base url lock");
            let previous = std::env::var("FATOORA_ZATCA_BASE_URL").ok();
            unsafe {
                std::env::set_var("FATOORA_ZATCA_BASE_URL", url);
            }
            Self {
                _lock: lock,
                previous,
            }
        }
    }

    impl Drop for BaseUrlGuard {
        fn drop(&mut self) {
            match self.previous.as_ref() {
                Some(value) => unsafe {
                    std::env::set_var("FATOORA_ZATCA_BASE_URL", value);
                },
                None => unsafe {
                    std::env::remove_var("FATOORA_ZATCA_BASE_URL");
                },
            }
        }
    }

    fn try_start_server() -> Option<MockServer> {
        std::panic::catch_unwind(MockServer::start).ok()
    }

    #[test]
    fn zatca_invoice_endpoints_use_base_url() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));
        let body = r#"{
          "validationResults": {
            "infoMessages": [],
            "warningMessages": [],
            "errorMessages": [],
            "status": "PASS"
          },
          "reportingStatus": "REPORTED",
          "clearanceStatus": null,
          "qrSellertStatus": null,
          "qrBuyertStatus": null
        }"#;

        let report_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/invoices/reporting/single")
                .header("accept-language", "ar");
            then.status(200)
                .header("content-type", "application/json")
                .body(body);
        });

        let clear_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/invoices/clearance/single")
                .header("accept-language", "en");
            then.status(200)
                .header("content-type", "application/json")
                .body(body);
        });

        let compliance_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/compliance/invoices")
                .header("accept-language", "en");
            then.status(200)
                .header("content-type", "application/json")
                .body(body);
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let simplified = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Simplified));
            let standard = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Standard));
            let pcsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                None,
                "token",
                "secret",
            );
            let ccsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                None,
                "token",
                "secret",
            );

            let report = client
                .report_simplified_invoice(&simplified, &pcsid, false, Some("ar"))
                .await;
            assert!(report.is_ok());
            let clear = client
                .clear_standard_invoice(&standard, &pcsid, true, None)
                .await;
            assert!(clear.is_ok());
            let compliance = client.check_invoice_compliance(&simplified, &ccsid).await;
            assert!(compliance.is_ok());

            report_mock.assert();
            clear_mock.assert();
            compliance_mock.assert();
        });
    }

    #[test]
    fn zatca_csid_endpoints_use_base_url() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));
        let ccsid_body = r#"{
          "requestID": 42,
          "binarySecurityToken": "token",
          "secret": "secret"
        }"#;
        let pcsid_body = r#"{
          "requestID": 77,
          "binarySecurityToken": "ptoken",
          "secret": "psecret"
        }"#;
        let renew_body = r#"{
          "value": {
            "requestID": 88,
            "binarySecurityToken": "rtoken",
            "secret": "rsecret"
          }
        }"#;

        let csr_mock = server.mock(|when, then| {
            when.method(POST).path("/compliance").header("OTP", "123456");
            then.status(200)
                .header("content-type", "application/json")
                .body(ccsid_body);
        });
        let pcsid_mock = server.mock(|when, then| {
            when.method(POST).path("/production/csids");
            then.status(200)
                .header("content-type", "application/json")
                .body(pcsid_body);
        });
        let renew_mock = server.mock(|when, then| {
            when.method(PATCH)
                .path("/production/csids")
                .header("accept-language", "ar");
            then.status(428)
                .header("content-type", "application/json")
                .body(renew_body);
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let csr = build_csr();
            let ccsid = client
                .post_csr_for_ccsid(&csr, "123456")
                .await
                .expect("ccsid");
            assert_eq!(ccsid.request_id(), Some(42));

            let pcsid = client
                .post_ccsid_for_pcsid(&ccsid)
                .await
                .expect("pcsid");
            assert_eq!(pcsid.request_id(), Some(77));

            let renewed = client
                .renew_csid(&pcsid, &csr, "123456", Some("ar"))
                .await
                .expect("renew");
            assert_eq!(renewed.request_id(), Some(88));

            csr_mock.assert();
            pcsid_mock.assert();
            renew_mock.assert();
        });
    }

    #[test]
    fn report_handles_unauthorized_and_not_acceptable() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));
        let unauthorized = r#"{"status":401,"error":"Unauthorized","message":"nope"}"#;

        let mut unauthorized_mock = server.mock(|when, then| {
            when.method(POST).path("/invoices/reporting/single");
            then.status(401)
                .header("content-type", "application/json")
                .body(unauthorized);
        });

        let not_acceptable_mock = server.mock(|when, then| {
            when.method(POST).path("/invoices/reporting/single");
            then.status(406).body("nope");
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let invoice = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Simplified));
            let creds = CsidCredentials::new(
                EnvironmentType::NonProduction,
                None,
                "token",
                "secret",
            );

            let result = client
                .report_simplified_invoice(&invoice, &creds, false, None)
                .await;
            assert!(matches!(result, Err(ZatcaError::Unauthorized(_))));

            unauthorized_mock.delete();

            let result = client
                .report_simplified_invoice(&invoice, &creds, false, None)
                .await;
            assert!(matches!(result, Err(ZatcaError::InvalidResponse(_))));

            not_acceptable_mock.assert();
        });
    }

    #[test]
    fn report_and_clear_handle_server_error_and_unauthorized() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));

        let report_mock = server.mock(|when, then| {
            when.method(POST).path("/invoices/reporting/single");
            then.status(500)
                .header("content-type", "application/json")
                .body(r#"{"category":"Server","code":"ERR","message":"boom"}"#);
        });

        let clear_mock = server.mock(|when, then| {
            when.method(POST).path("/invoices/clearance/single");
            then.status(401)
                .header("content-type", "application/json")
                .body(r#"{"status":401,"error":"Unauthorized","message":"nope"}"#);
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let simplified = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Simplified));
            let standard = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Standard));
            let pcsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                None,
                "token",
                "secret",
            );

            let result = client
                .report_simplified_invoice(&simplified, &pcsid, false, None)
                .await;
            assert!(matches!(result, Err(ZatcaError::ServerError(_))));

            let result = client
                .clear_standard_invoice(&standard, &pcsid, true, None)
                .await;
            assert!(matches!(result, Err(ZatcaError::Unauthorized(_))));

            report_mock.assert();
            clear_mock.assert();
        });
    }

    #[test]
    fn clear_and_compliance_error_paths() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));

        let clear_mock = server.mock(|when, then| {
            when.method(POST).path("/invoices/clearance/single");
            then.status(200).body("not json");
        });

        let compliance_mock = server.mock(|when, then| {
            when.method(POST).path("/compliance/invoices");
            then.status(500)
                .header("content-type", "application/json")
                .body(r#"{"category":"Server","code":"ERR","message":"boom"}"#);
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let standard = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Standard));
            let simplified = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Simplified));
            let pcsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                None,
                "token",
                "secret",
            );
            let ccsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                None,
                "token",
                "secret",
            );

            let result = client
                .clear_standard_invoice(&standard, &pcsid, true, None)
                .await;
            assert!(matches!(result, Err(ZatcaError::InvalidResponse(_))));

            let result = client.check_invoice_compliance(&simplified, &ccsid).await;
            assert!(matches!(result, Err(ZatcaError::ServerError(_))));

            clear_mock.assert();
            compliance_mock.assert();
        });
    }

    #[test]
    fn report_handles_conflict_response() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));
        let body = r#"{
          "validationResults": {
            "infoMessages": [],
            "warningMessages": [],
            "errorMessages": [],
            "status": "PASS"
          },
          "reportingStatus": "REPORTED",
          "clearanceStatus": null,
          "qrSellertStatus": null,
          "qrBuyertStatus": null
        }"#;

        let report_mock = server.mock(|when, then| {
            when.method(POST).path("/invoices/reporting/single");
            then.status(409)
                .header("content-type", "application/json")
                .body(body);
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let invoice = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Simplified));
            let pcsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                None,
                "token",
                "secret",
            );

            let result = client
                .report_simplified_invoice(&invoice, &pcsid, false, None)
                .await;
            assert!(result.is_ok());

            report_mock.assert();
        });
    }

    #[test]
    fn clear_handles_server_error() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));

        let clear_mock = server.mock(|when, then| {
            when.method(POST).path("/invoices/clearance/single");
            then.status(500)
                .header("content-type", "application/json")
                .body(r#"{"category":"Server","code":"ERR","message":"boom"}"#);
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let invoice = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Standard));
            let pcsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                None,
                "token",
                "secret",
            );

            let result = client
                .clear_standard_invoice(&invoice, &pcsid, true, None)
                .await;
            assert!(matches!(result, Err(ZatcaError::ServerError(_))));

            clear_mock.assert();
        });
    }

    #[test]
    fn compliance_handles_unauthorized() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));

        let compliance_mock = server.mock(|when, then| {
            when.method(POST).path("/compliance/invoices");
            then.status(401)
                .header("content-type", "application/json")
                .body(r#"{"status":401,"error":"Unauthorized","message":"nope"}"#);
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let invoice = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Simplified));
            let ccsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                None,
                "token",
                "secret",
            );

            let result = client.check_invoice_compliance(&invoice, &ccsid).await;
            assert!(matches!(result, Err(ZatcaError::Unauthorized(_))));

            compliance_mock.assert();
        });
    }

    #[test]
    fn csid_requests_handle_invalid_and_unauthorized() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));

        let csr_mock = server.mock(|when, then| {
            when.method(POST).path("/compliance");
            then.status(400).body("bad");
        });

        let pcsid_mock = server.mock(|when, then| {
            when.method(POST).path("/production/csids");
            then.status(400).body("bad");
        });

        let renew_mock = server.mock(|when, then| {
            when.method(PATCH).path("/production/csids");
            then.status(401)
                .header("content-type", "application/json")
                .body(r#"{"status":401,"error":"Unauthorized","message":"nope"}"#);
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let csr = build_csr();

            let result = client.post_csr_for_ccsid(&csr, "123456").await;
            assert!(matches!(result, Err(ZatcaError::InvalidResponse(_))));

            let ccsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                Some(10),
                "token",
                "secret",
            );
            let result = client.post_ccsid_for_pcsid(&ccsid).await;
            assert!(matches!(result, Err(ZatcaError::InvalidResponse(_))));

            let pcsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                Some(11),
                "token",
                "secret",
            );
            let result = client
                .renew_csid(&pcsid, &csr, "123456", None)
                .await;
            assert!(matches!(result, Err(ZatcaError::Unauthorized(_))));

            csr_mock.assert();
            pcsid_mock.assert();
            renew_mock.assert();
        });
    }

    #[test]
    fn compliance_and_renew_invalid_response_paths() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));

        let compliance_mock = server.mock(|when, then| {
            when.method(POST).path("/compliance/invoices");
            then.status(200).body("not json");
        });

        let renew_mock = server.mock(|when, then| {
            when.method(PATCH).path("/production/csids");
            then.status(418).body("nope");
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let invoice = build_signed_invoice(InvoiceType::Tax(InvoiceSubType::Simplified));
            let ccsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                None,
                "token",
                "secret",
            );
            let pcsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                Some(1),
                "token",
                "secret",
            );
            let csr = build_csr();

            let result = client.check_invoice_compliance(&invoice, &ccsid).await;
            assert!(matches!(result, Err(ZatcaError::InvalidResponse(_))));

            let result = client
                .renew_csid(&pcsid, &csr, "123456", None)
                .await;
            assert!(matches!(result, Err(ZatcaError::InvalidResponse(_))));

            compliance_mock.assert();
            renew_mock.assert();
        });
    }

    #[test]
    fn csid_requests_handle_invalid_json() {
        let server = match try_start_server() {
            Some(server) => server,
            None => return,
        };
        let _guard = BaseUrlGuard::new(&format!("{}/", server.base_url()));

        let csr_mock = server.mock(|when, then| {
            when.method(POST).path("/compliance");
            then.status(200).body("not json");
        });

        let pcsid_mock = server.mock(|when, then| {
            when.method(POST).path("/production/csids");
            then.status(200).body("not json");
        });

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let client = ZatcaClient::new(Config::default()).expect("client");
            let csr = build_csr();

            let result = client.post_csr_for_ccsid(&csr, "123456").await;
            assert!(matches!(result, Err(ZatcaError::InvalidResponse(_))));

            let ccsid = CsidCredentials::new(
                EnvironmentType::NonProduction,
                Some(10),
                "token",
                "secret",
            );
            let result = client.post_ccsid_for_pcsid(&ccsid).await;
            assert!(matches!(result, Err(ZatcaError::InvalidResponse(_))));

            csr_mock.assert();
            pcsid_mock.assert();
        });
    }

    fn build_csr() -> CertReq {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/csr-configs/csr-config-example-EN.properties");
        let csr_config = CsrProperties::parse_csr_config(&config_path).expect("csr config");
        let (csr, _key) = csr_config
            .build_with_rng(EnvironmentType::NonProduction)
            .expect("csr build");
        csr
    }

    fn build_signed_invoice(invoice_type: InvoiceType) -> SignedInvoice {
        let seller = Party::<SellerRole>::new(
            "Acme Inc".into(),
            Address {
                country_code: CountryCode::SAU,
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
        .expect("seller");

        let line_item = LineItem::new(crate::invoice::LineItemFields {
            description: "Item".into(),
            quantity: 1.0,
            unit_code: "PCE".into(),
            unit_price: 100.0,
            vat_rate: 15.0,
            vat_category: VatCategory::Standard,
        });

        let issue_datetime = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(12, 30, 0)
            .unwrap();

        let invoice = InvoiceBuilder::new(RequiredInvoiceFields {
            invoice_type,
            id: "INV-TEST-1".into(),
            uuid: "uuid-test-1".into(),
            issue_datetime: chrono::Utc.from_utc_datetime(&issue_datetime),
            currency: Currency::SAR,
            previous_invoice_hash: "".into(),
            invoice_counter: 0,
            seller,
            line_items: vec![line_item],
            payment_means_code: "10".into(),
            vat_category: VatCategory::Standard,
        })
        .build()
        .expect("build invoice");

        let signed_xml = invoice.to_xml().expect("serialize invoice");
        let public_key_b64 = Base64::encode_string(b"pk");
        let signing =
            SignedProperties::from_qr_parts("hash==", "signature==", &public_key_b64, None);
        invoice
            .sign_with_bundle(signing, signed_xml)
            .expect("sign invoice")
    }
}
