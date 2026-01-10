use anyhow::Result;
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
    pub validation_results: ValidationResults,
    #[serde(rename = "reportingStatus")]
    pub reporting_status: Option<String>,
    #[serde(rename = "clearanceStatus")]
    pub clearance_status: Option<String>,
    #[serde(rename = "qrSellertStatus")]
    pub qr_seller_status: Option<String>,
    #[serde(rename = "qrBuyertStatus")]
    pub qr_buyer_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResults {
    #[serde(rename = "infoMessages", default)]
    pub info_messages: MessageList,
    #[serde(rename = "warningMessages", default)]
    pub warning_messages: Vec<ValidationMessage>,
    #[serde(rename = "errorMessages", default)]
    pub error_messages: Vec<ValidationMessage>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationMessage {
    #[serde(rename = "type")]
    pub message_type: Option<String>,
    pub code: Option<String>,
    pub category: Option<String>,
    pub message: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
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
    pub timestamp: Option<i64>,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerErrorResponse {
    pub category: Option<String>,
    pub code: Option<String>,
    pub message: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsidCredentials<T> {
    pub env: EnvironmentType,
    pub request_id: Option<u64>,
    pub binary_security_token: String,
    pub secret: String,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> CsidCredentials<T> {
    fn new(
        env: EnvironmentType,
        request_id: Option<u64>,
        binary_security_token: String,
        secret: String,
    ) -> Self {
        Self {
            env,
            request_id,
            binary_security_token,
            secret,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Deserialize)]
struct CsidResponseBody {
    #[serde(rename = "requestID")]
    request_id: Option<u64>,
    #[serde(rename = "binarySecurityToken")]
    binary_security_token: String,
    secret: String,
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
        if !invoice.data().invoice_type.is_simplified() {
            return Err(ZatcaError::ClientState(
                "Reporting only supports simplified invoices".into(),
            ));
        }

        let payload = serde_json::json!({
            "invoiceHash": invoice.invoice_hash(),
            "uuid": invoice.uuid(),
            "invoice": invoice.xml_base64()
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
                credentials.binary_security_token.clone(),
                Some(credentials.secret.clone()),
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

    pub fn clear_standard_invoice(&self, _invoice: &SignedInvoice) -> Result<(), ZatcaError> {
        todo!()
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
            "invoice": invoice.xml_base64()
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
                credentials.binary_security_token.clone(),
                Some(credentials.secret.clone()),
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
            self.config.env,
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
            .request_id
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
                ccsid.binary_security_token.clone(),
                Some(ccsid.secret.clone()),
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
            self.config.env,
            payload.request_id,
            payload.binary_security_token,
            payload.secret,
        ))
    }

    pub fn renew_csid(
        &self,
        _pcsid: &CsidCredentials<Compliance>,
    ) -> Result<CsidCredentials<Production>, ZatcaError> {
        todo!()
    }
}

// Private API
impl ZatcaClient {
    fn build_endpoint(&self, path: &str) -> String {
        format!(
            "{}{}",
            self.config.env.get_endpoint_url(),
            path.trim_start_matches('/')
        )
    }

    fn ensure_env<T>(&self, creds: &CsidCredentials<T>) -> Result<(), ZatcaError> {
        if creds.env != self.config.env {
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
            InvoiceType, LineItem, Party, SellerRole, VatCategory,
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

    #[tokio::test]
    async fn report_rejects_standard_invoice() {
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

        let line_item = LineItem {
            description: "Item".into(),
            quantity: 1.0,
            unit_code: "PCE".into(),
            unit_price: 100.0,
            total_amount: 100.0,
            vat_rate: 15.0,
            vat_amount: 15.0,
            vat_category: VatCategory::Standard,
        };

        let issue_datetime = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(12, 30, 0)
            .unwrap();

        let invoice = InvoiceBuilder::new(
            InvoiceType::Tax(InvoiceSubType::Standard),
            "INV-STD-1",
            "uuid-std-1",
            chrono::Utc.from_utc_datetime(&issue_datetime),
            Currency::SAR,
            "",
            seller,
            vec![line_item],
            "10",
            VatCategory::Standard,
        )
        .build()
        .expect("build invoice");

        let signed_xml = invoice.to_xml().expect("serialize invoice");
        let public_key_b64 = Base64::encode_string(b"pk");
        let signing =
            SignedProperties::from_qr_parts("hash==", "signature==", &public_key_b64, None);
        let signed_invoice = invoice
            .sign_with_bundle(signing, signed_xml)
            .expect("sign invoice");

        let creds = CsidCredentials::new(
            EnvironmentType::NonProduction,
            None,
            "token".into(),
            "secret".into(),
        );
        let client = ZatcaClient::new(Config::default()).expect("client");

        let result = client
            .report_simplified_invoice(&signed_invoice, &creds, false, None)
            .await;
        assert!(matches!(result, Err(ZatcaError::ClientState(_))));
    }
}
