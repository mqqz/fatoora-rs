use std::marker::PhantomData;

use anyhow::Result;
use base64ct::{Base64, Encoding};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use x509_cert::request::CertReq;

use crate::{config::Config, csr::ToBase64String, invoice::Invoice};

#[derive(Error, Debug)]
pub enum ZatcaError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Invalid response from ZATCA: {0}")]
    InvalidResponse(String),
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
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

#[derive(Debug, Deserialize)]
pub struct CsidResponse<T: TokenScope> {
    #[serde(skip)]
    _marker: PhantomData<T>,
    #[serde(rename = "requestID")]
    pub request_id: u64,
    #[serde(rename = "dispositionMessage")]
    pub disposition_message: String,
    #[serde(rename = "binarySecurityToken")]
    pub binary_security_token: String,
    pub secret: String,
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

    pub fn report_simplified_invoice(&self, _invoice: &Invoice) -> Result<(), ZatcaError> {
        todo!()
    }

    pub fn clear_standard_invoice(&self, _invoice: &Invoice) -> Result<(), ZatcaError> {
        todo!()
    }

    pub fn check_invoice_compliance(&self, _invoice: &Invoice) -> Result<(), ZatcaError> {
        todo!()
    }

    pub async fn post_csr_for_ccsid(
        &self,
        csr: &CertReq,
        otp: &str,
    ) -> Result<CsidResponse<Compliance>, ZatcaError> {
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

        response
            .json()
            .await
            .map_err(|e| ZatcaError::InvalidResponse(e.to_string()))
    }

    pub async fn post_ccsid_for_pccsid(
        &self,
        ccsid: &CsidResponse<Compliance>,
    ) -> Result<CsidResponse<Production>, ZatcaError> {
        let payload = serde_json::json!({
            "compliance_request_id": ccsid.request_id,
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

        response
            .json()
            .await
            .map_err(|e| ZatcaError::InvalidResponse(e.to_string()))
    }

    pub fn renew_csid(
        &self,
        pcsid: &CsidResponse<Compliance>,
    ) -> Result<CsidResponse<Production>, ZatcaError> {
        todo!()
    }
}

// Private API
impl ZatcaClient {
    fn prepare_invoice_payload(&self, _invoice: &Invoice) -> Result<Value, ZatcaError> {
        // TODO: transform the internal invoice model to the JSON payload required by ZATCA
        todo!()
    }

    fn build_endpoint(&self, path: &str) -> String {
        format!(
            "{}{}",
            self.config.env.get_endpoint_url(),
            path.trim_start_matches('/')
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64, Encoding};
    use std::path::Path;
    use x509_cert::der::Decode;

    #[tokio::test]
    async fn post_compliance_csid_sandbox() {
        let otp = "123345";
        let csr_path = Path::new("../assets/csrs/test_zatca_en1.csr");
        let csr_b64 = std::fs::read_to_string(csr_path).expect("read CSR");
        let csr_der = Base64::decode_vec(csr_b64.trim()).expect("decode CSR base64");
        let csr = CertReq::from_der(&csr_der).expect("parse CSR");

        let client = ZatcaClient::new(Config::default()).expect("client builds");

        let response = client
            .post_csr_for_ccsid(&csr, otp)
            .await
            .expect("CSID request succeeds");
        println!("CSID Response: {:?}", response);
        assert!(
            !response.binary_security_token.is_empty(),
            "empty binary_security_token. response: {:?}",
            response
        );
        assert!(
            !response.secret.is_empty(),
            "empty secret. response: {:?}",
            response
        );
    }

    #[tokio::test]
    async fn post_production_csid_sandbox() {
        let otp = "123345";
        let csr_path = Path::new("../assets/csrs/test_zatca_en1.csr");
        let csr_b64 = std::fs::read_to_string(csr_path).expect("read CSR");
        let csr_der = Base64::decode_vec(csr_b64.trim()).expect("decode CSR base64");
        let csr = CertReq::from_der(&csr_der).expect("parse CSR");
        let client = ZatcaClient::new(Config::default()).expect("client builds");
        let compliance_response = client
            .post_csr_for_ccsid(&csr, otp)
            .await
            .expect("CSID request succeeds");
        println!("Compliance CSID Response: {:?}", compliance_response);
        let production_response = client
            .post_ccsid_for_pccsid(&compliance_response)
            .await
            .expect("Production CSID request succeeds");
        println!("Production CSID Response: {:?}", production_response);
        assert!(
            !production_response.binary_security_token.is_empty(),
            "empty binary_security_token. response: {:?}",
            production_response
        );
        assert!(
            !production_response.secret.is_empty(),
            "empty secret. response: {:?}",
            production_response
        );
    }
}
