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

pub trait TokenScope {}
#[derive(Debug)]
pub struct Compliance;
#[derive(Debug)]
pub struct Production;
impl TokenScope for Compliance {}
impl TokenScope for Production {}

pub struct ZatcaClient {
    config: Config,
    _client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[derive(Default)]
pub enum MessageList {
    One(ValidationMessage),
    Many(Vec<ValidationMessage>),
    #[default]
    Empty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsidCredentials<T> {
    env: EnvironmentType,
    request_id: Option<u64>,
    binary_security_token: String,
    secret: String,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> CsidCredentials<T> {
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
    pub fn new(config: Config) -> Result<Self, ZatcaError> {
        let client = Client::builder().build().map_err(ZatcaError::Http)?;

        Ok(Self {
            config,
            _client: client,
        })
    }

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
            self.config.env().endpoint_url(),
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
        invoice::{
            sign::SignedProperties, xml::ToXml, Address, InvoiceBuilder, InvoiceSubType,
            InvoiceType, LineItem, Party, RequiredInvoiceFields, SellerRole, VatCategory,
        },
    };
    use base64ct::{Base64, Encoding};
    use chrono::TimeZone;
    use isocountry::CountryCode;
    use iso_currency::Currency;

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

    fn build_signed_invoice(invoice_type: InvoiceType) -> SignedInvoice {
        let seller = Party::<SellerRole>::new(
            "Acme Inc".into(),
            Address::new(
                CountryCode::SAU,
                "Riyadh",
                "King Fahd",
                None,
                "1234",
                Some("5678".into()),
                "12222",
                None,
                None,
            ),
            "301121971500003",
            None,
        )
        .expect("seller");

        let line_item = LineItem::new(
            "Item",
            1.0,
            "PCE",
            100.0,
            100.0,
            15.0,
            15.0,
            VatCategory::Standard,
        );

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
