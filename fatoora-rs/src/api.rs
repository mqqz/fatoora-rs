use std::sync::{Arc, Mutex};

use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;
use x509_cert::request::CertReq;

use crate::{config::Config, invoice::Invoice, pcsid::PcsidResponse};

pub fn generate(_path: &str) -> Result<String> {
    // TODO: transform invoice XML -> JSON API request structure
    todo!()
}

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

#[derive(Debug, Default)]
struct ZatcaAuthTokens {
    compliance: Option<String>,
    production: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum TokenScope {
    Compliance,
    Production,
}

pub struct ZatcaClient {
    config: Config,
    base_url: String,
    http: Client,
    tokens: Arc<Mutex<ZatcaAuthTokens>>,
}

impl ZatcaClient {
    pub fn new(config: Config) -> Result<Self, ZatcaError> {
        let base_url = config.env.get_endpoint_url().to_string();
        let http = Client::builder().build().map_err(ZatcaError::Http)?;

        Ok(Self {
            config,
            base_url,
            http,
            tokens: Arc::new(Mutex::new(ZatcaAuthTokens::default())),
        })
    }

    pub fn report_simplified_invoice(&self, invoice: &Invoice) -> Result<(), ZatcaError> {
        let payload = self.prepare_invoice_payload(invoice, InvoiceType::Simplified)?;
        self.send_request::<_, ()>(
            "invoices/reporting/simplified",
            &payload,
            TokenScope::Production,
        )
    }

    pub fn clear_standard_invoice(&self, invoice: &Invoice) -> Result<(), ZatcaError> {
        let payload = self.prepare_invoice_payload(invoice, InvoiceType::Standard)?;
        self.send_request::<_, ()>(
            "invoices/clearing/standard",
            &payload,
            TokenScope::Production,
        )
    }

    pub fn check_invoice_compliance(&self, invoice: &Invoice) -> Result<(), ZatcaError> {
        let payload = self.prepare_invoice_payload(invoice, InvoiceType::Standard)?;
        self.send_request::<_, ()>(
            "compliance/invoices/check",
            &payload,
            TokenScope::Compliance,
        )
    }

    pub fn post_compliance_csid(&self, csr: &CertReq) -> Result<PcsidResponse, ZatcaError> {
        let payload = self.prepare_csr_payload(csr)?;
        self.send_request("compliance/csid", &payload, TokenScope::Compliance)
    }

    pub fn post_production_csid(&self, csr: &CertReq) -> Result<PcsidResponse, ZatcaError> {
        let payload = self.prepare_csr_payload(csr)?;
        self.send_request("production/csid", &payload, TokenScope::Production)
    }

    pub fn renew_csid(&self, csr: &CertReq) -> Result<PcsidResponse, ZatcaError> {
        let payload = self.prepare_csr_payload(csr)?;
        self.send_request("production/csid/renew", &payload, TokenScope::Production)
    }

    fn prepare_invoice_payload(
        &self,
        _invoice: &Invoice,
        _invoice_type: InvoiceType,
    ) -> Result<Value, ZatcaError> {
        // TODO: transform the internal invoice model to the JSON payload required by ZATCA
        todo!()
    }

    fn prepare_csr_payload(&self, _csr: &CertReq) -> Result<Value, ZatcaError> {
        // TODO: serialize CSR details into the payload expected by the CSID endpoints
        todo!()
    }

    fn send_request<Request, Response>(
        &self,
        path: &str,
        body: &Request,
        scope: TokenScope,
    ) -> Result<Response, ZatcaError>
    where
        Request: Serialize + ?Sized,
        Response: DeserializeOwned,
    {
        let url = self.build_endpoint(path);
        let _token = self.ensure_token(scope)?;

        // TODO: attach headers, authentication tokens, and handle retries
        let _ = (&self.http, url, body);
        todo!()
    }

    fn ensure_token(&self, scope: TokenScope) -> Result<String, ZatcaError> {
        let token_store = self
            .tokens
            .lock()
            .map_err(|_| ZatcaError::ClientState("token store lock poisoned".into()))?;

        let token = match scope {
            TokenScope::Compliance => token_store.compliance.clone(),
            TokenScope::Production => token_store.production.clone(),
        };

        token.ok_or_else(|| ZatcaError::AuthenticationFailed("token not initialized".into()))
    }

    fn build_endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }
}

#[derive(Clone, Copy)]
enum InvoiceType {
    Simplified,
    Standard,
}
