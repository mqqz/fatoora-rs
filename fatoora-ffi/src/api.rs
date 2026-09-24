//! Owned ZATCA credentials and blocking HTTP operations for generated bindings.
use crate::common::ffi::{BindingError, Text};
use crate::common::{boundary, core_error, local_error, text, write};
use diplomat_runtime::DiplomatStr;
use fatoora_core::api as core;
use std::sync::OnceLock;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

// Enter Tokio on a scoped worker so callers already inside a runtime remain supported.
// The worker cannot outlive borrowed invoice, credentials, or client objects.
fn run<T: Send>(
    future: impl std::future::Future<Output = Result<T, core::ZatcaError>> + Send,
) -> Result<T, Box<BindingError>> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("fatoora-http".into())
            .spawn_scoped(scope, move || {
                boundary(|| {
                    if RUNTIME.get().is_none() {
                        let runtime = tokio::runtime::Runtime::new().map_err(|err| {
                            local_error(9, &format!("runtime init failed: {err}"))
                        })?;
                        let _ = RUNTIME.set(runtime);
                    }
                    RUNTIME
                        .get()
                        .expect("runtime initialized")
                        .block_on(future)
                        .map_err(core_error)
                })
            })
            .map_err(|err| local_error(9, &format!("HTTP worker failed: {err}")))?
            .join()
            .map_err(|payload| {
                if let Err(nested) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
                {
                    std::mem::forget(nested);
                }
                local_error(9, "HTTP worker panicked")
            })?
    })
}

fn optional(value: Option<&str>) -> Result<Option<Box<Text>>, Box<BindingError>> {
    value
        .map(|value| {
            if value.contains('\0') {
                return Err(local_error(1, "output contains NUL"));
            }
            Ok(Box::new(Text(value.to_owned())))
        })
        .transpose()
}

fn optional_input(value: Option<&DiplomatStr>) -> Result<Option<&str>, Box<BindingError>> {
    value.map(text).transpose()
}

#[diplomat::bridge]
#[diplomat::abi_rename = "fatoora_{0}"]
#[diplomat::attr(cpp, namespace = "fatoora")]
pub mod ffi {
    use super::{boundary, core_error, local_error, optional, optional_input, run, text, write};
    use crate::common::ffi::{BindingError, Text};
    use crate::crypto::ffi::{Config, Csr};
    use crate::invoice::ffi::SignedInvoice;
    use diplomat_runtime::{DiplomatStr, DiplomatWrite};

    #[diplomat::opaque]
    #[diplomat::attr(
        nanobind,
        custom_extra_code(file = "client_bindings.cpp", location = "init_block")
    )]
    pub struct ZatcaClient(pub(crate) fatoora_core::api::ZatcaClient);
    #[diplomat::opaque]
    pub struct CsidCompliance(
        pub(crate) fatoora_core::api::CsidCredentials<fatoora_core::api::Compliance>,
    );
    #[diplomat::opaque]
    pub struct CsidProduction(
        pub(crate) fatoora_core::api::CsidCredentials<fatoora_core::api::Production>,
    );
    #[diplomat::opaque]
    pub struct ValidationResponse(pub(crate) fatoora_core::api::ValidationResponse);
    #[diplomat::opaque]
    pub struct ValidationResults(pub(crate) fatoora_core::api::ValidationResults);
    #[diplomat::opaque]
    pub struct ValidationMessage(pub(crate) fatoora_core::api::ValidationMessage);

    pub enum InvoiceOutcome {
        Unknown = 0,
        Accepted = 1,
        Rejected = 2,
    }

    impl CsidCompliance {
        pub fn create(
            environment: u8,
            request_id: Option<&DiplomatStr>,
            token: &DiplomatStr,
            secret: &DiplomatStr,
        ) -> Result<Box<Self>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(fatoora_core::api::CsidCredentials::<
                    fatoora_core::api::Compliance,
                >::new(
                    crate::common::environment(environment)?,
                    optional_input(request_id)?.map(str::to_owned),
                    text(token)?,
                    text(secret)?,
                ))))
            })
        }
        pub fn env(&self) -> u8 {
            match self.0.env() {
                fatoora_core::config::EnvironmentType::NonProduction => 0,
                fatoora_core::config::EnvironmentType::Simulation => 1,
                fatoora_core::config::EnvironmentType::Production => 2,
            }
        }
        pub fn request_id(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.request_id()))
        }
        pub fn binary_security_token(
            &self,
            output: &mut DiplomatWrite,
        ) -> Result<(), Box<BindingError>> {
            boundary(|| write(self.0.binary_security_token(), output))
        }
        pub fn secret(&self, output: &mut DiplomatWrite) -> Result<(), Box<BindingError>> {
            boundary(|| write(self.0.secret(), output))
        }
    }

    impl CsidProduction {
        pub fn create(
            environment: u8,
            request_id: Option<&DiplomatStr>,
            token: &DiplomatStr,
            secret: &DiplomatStr,
        ) -> Result<Box<Self>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(Self(fatoora_core::api::CsidCredentials::<
                    fatoora_core::api::Production,
                >::new(
                    crate::common::environment(environment)?,
                    optional_input(request_id)?.map(str::to_owned),
                    text(token)?,
                    text(secret)?,
                ))))
            })
        }
        pub fn env(&self) -> u8 {
            match self.0.env() {
                fatoora_core::config::EnvironmentType::NonProduction => 0,
                fatoora_core::config::EnvironmentType::Simulation => 1,
                fatoora_core::config::EnvironmentType::Production => 2,
            }
        }
        pub fn request_id(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.request_id()))
        }
        pub fn binary_security_token(
            &self,
            output: &mut DiplomatWrite,
        ) -> Result<(), Box<BindingError>> {
            boundary(|| write(self.0.binary_security_token(), output))
        }
        pub fn secret(&self, output: &mut DiplomatWrite) -> Result<(), Box<BindingError>> {
            boundary(|| write(self.0.secret(), output))
        }
    }

    impl ZatcaClient {
        pub fn create(config: &Config) -> Result<Box<Self>, Box<BindingError>> {
            boundary(|| {
                fatoora_core::api::ZatcaClient::new(config.0.clone())
                    .map(|value| Box::new(Self(value)))
                    .map_err(core_error)
            })
        }
        pub fn post_csr_for_ccsid(
            &self,
            csr: &Csr,
            otp: &DiplomatStr,
        ) -> Result<Box<CsidCompliance>, Box<BindingError>> {
            boundary(|| {
                run(self.0.post_csr_for_ccsid(&csr.0, text(otp)?))
                    .map(|value| Box::new(CsidCompliance(value)))
            })
        }
        pub fn post_ccsid_for_pcsid(
            &self,
            credentials: &CsidCompliance,
        ) -> Result<Box<CsidProduction>, Box<BindingError>> {
            boundary(|| {
                run(self.0.post_ccsid_for_pcsid(&credentials.0))
                    .map(|value| Box::new(CsidProduction(value)))
            })
        }
        pub fn renew_csid(
            &self,
            credentials: &CsidProduction,
            csr: &Csr,
            otp: &DiplomatStr,
            accept_language: Option<&DiplomatStr>,
        ) -> Result<Box<CsidProduction>, Box<BindingError>> {
            boundary(|| {
                run(self.0.renew_csid(
                    &credentials.0,
                    &csr.0,
                    text(otp)?,
                    optional_input(accept_language)?,
                ))
                .map(|value| Box::new(CsidProduction(value)))
            })
        }
        pub fn check_invoice_compliance(
            &self,
            invoice: &SignedInvoice,
            credentials: &CsidCompliance,
        ) -> Result<Box<ValidationResponse>, Box<BindingError>> {
            boundary(|| {
                let invoice = invoice
                    .0
                    .as_ref()
                    .ok_or_else(|| local_error(1, "signed invoice has been consumed"))?;
                run(self.0.check_invoice_compliance(invoice, &credentials.0))
                    .map(|value| Box::new(ValidationResponse(value)))
            })
        }
        pub fn report_simplified_invoice(
            &self,
            invoice: &SignedInvoice,
            credentials: &CsidProduction,
            clearance_status: bool,
            accept_language: Option<&DiplomatStr>,
        ) -> Result<Box<ValidationResponse>, Box<BindingError>> {
            boundary(|| {
                let invoice = invoice
                    .0
                    .as_ref()
                    .ok_or_else(|| local_error(1, "signed invoice has been consumed"))?;
                run(self.0.report_simplified_invoice(
                    invoice,
                    &credentials.0,
                    clearance_status,
                    optional_input(accept_language)?,
                ))
                .map(|value| Box::new(ValidationResponse(value)))
            })
        }
        pub fn clear_standard_invoice(
            &self,
            invoice: &SignedInvoice,
            credentials: &CsidProduction,
            clearance_status: bool,
            accept_language: Option<&DiplomatStr>,
        ) -> Result<Box<ValidationResponse>, Box<BindingError>> {
            boundary(|| {
                let invoice = invoice
                    .0
                    .as_ref()
                    .ok_or_else(|| local_error(1, "signed invoice has been consumed"))?;
                run(self.0.clear_standard_invoice(
                    invoice,
                    &credentials.0,
                    clearance_status,
                    optional_input(accept_language)?,
                ))
                .map(|value| Box::new(ValidationResponse(value)))
            })
        }
    }
    impl ValidationResponse {
        pub fn http_status(&self) -> Option<u16> {
            self.0.http_status()
        }
        pub fn outcome(&self) -> InvoiceOutcome {
            match self.0.outcome() {
                fatoora_core::api::InvoiceOutcome::Accepted => InvoiceOutcome::Accepted,
                fatoora_core::api::InvoiceOutcome::Rejected => InvoiceOutcome::Rejected,
                _ => InvoiceOutcome::Unknown,
            }
        }
        pub fn ensure_accepted(&self) -> Result<(), Box<BindingError>> {
            boundary(|| self.0.ensure_accepted().map_err(core_error))
        }
        pub fn cleared_invoice_xml(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.cleared_invoice_xml().map_err(core_error)?.as_deref()))
        }
        pub fn validation_results(&self) -> Result<Box<ValidationResults>, Box<BindingError>> {
            boundary(|| {
                Ok(Box::new(ValidationResults(
                    self.0.validation_results().clone(),
                )))
            })
        }
        pub fn cleared_invoice_base64(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.cleared_invoice_base64()))
        }
        pub fn reporting_status(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.reporting_status()))
        }
        pub fn clearance_status(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.clearance_status()))
        }
        pub fn qr_seller_status(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.qr_seller_status()))
        }
        pub fn qr_buyer_status(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.qr_buyer_status()))
        }
    }
    impl ValidationResults {
        pub fn status(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.status()))
        }
        pub fn info_len(&self) -> usize {
            match self.0.info_messages() {
                fatoora_core::api::MessageList::One(_) => 1,
                fatoora_core::api::MessageList::Many(values) => values.len(),
                fatoora_core::api::MessageList::Empty => 0,
            }
        }
        pub fn info_message(
            &self,
            index: usize,
        ) -> Result<Box<ValidationMessage>, Box<BindingError>> {
            boundary(|| {
                let value = match self.0.info_messages() {
                    fatoora_core::api::MessageList::One(value) => (index == 0).then_some(value),
                    fatoora_core::api::MessageList::Many(values) => values.get(index),
                    fatoora_core::api::MessageList::Empty => None,
                };
                value
                    .cloned()
                    .map(|value| Box::new(ValidationMessage(value)))
                    .ok_or_else(|| local_error(1, "info message index out of range"))
            })
        }
        pub fn warning_len(&self) -> usize {
            self.0.warning_messages().len()
        }
        pub fn warning_message(
            &self,
            index: usize,
        ) -> Result<Box<ValidationMessage>, Box<BindingError>> {
            boundary(|| {
                self.0
                    .warning_messages()
                    .get(index)
                    .cloned()
                    .map(|value| Box::new(ValidationMessage(value)))
                    .ok_or_else(|| local_error(1, "warning message index out of range"))
            })
        }
        pub fn error_len(&self) -> usize {
            self.0.error_messages().len()
        }
        pub fn error_message(
            &self,
            index: usize,
        ) -> Result<Box<ValidationMessage>, Box<BindingError>> {
            boundary(|| {
                self.0
                    .error_messages()
                    .get(index)
                    .cloned()
                    .map(|value| Box::new(ValidationMessage(value)))
                    .ok_or_else(|| local_error(1, "error message index out of range"))
            })
        }
    }
    impl ValidationMessage {
        pub fn message_type(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.message_type()))
        }
        pub fn code(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.code()))
        }
        pub fn category(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.category()))
        }
        pub fn message(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.message()))
        }
        pub fn status(&self) -> Result<Option<Box<Text>>, Box<BindingError>> {
            boundary(|| optional(self.0.status()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ffi::*, run};

    #[test]
    fn blocking_adapter_supports_nested_runtime_and_contains_panics() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            assert_eq!(run(async { Ok(42) }).ok(), Some(42));
            let error = run::<()>(async { panic!("HTTP operation panic") })
                .err()
                .unwrap();
            assert_eq!(error.code(), 9);
            assert_eq!(run(async { Ok(43) }).ok(), Some(43));
        });
    }

    #[test]
    fn credentials_validate_environment_utf8_nul_and_optional_id() {
        assert!(CsidCompliance::create(3, None, b"token", b"secret").is_err());
        assert!(CsidProduction::create(0, None, b"\xff", b"secret").is_err());
        assert!(CsidCompliance::create(0, Some(b"id\0bad"), b"token", b"secret").is_err());
        let absent = CsidCompliance::create(1, None, b"token", b"secret")
            .ok()
            .unwrap();
        let empty = CsidProduction::create(2, Some(b""), b"token", b"secret")
            .ok()
            .unwrap();
        assert_eq!(absent.env(), 1);
        assert!(absent.request_id().ok().unwrap().is_none());
        assert_eq!(empty.env(), 2);
        assert_eq!(empty.request_id().ok().unwrap().unwrap().0, "");
    }

    #[test]
    fn detached_response_cannot_claim_acceptance_and_children_are_owned() {
        let response = ValidationResponse(
            serde_json::from_value(serde_json::json!({
                "http_status": 200,
                "reportingStatus": "REPORTED",
                "validationResults": {
                    "status": "PASS",
                    "infoMessages": {"code":"INFO", "message":"retained"},
                    "warningMessages": [{"code":"WARN"}],
                    "errorMessages": []
                }
            }))
            .unwrap(),
        );
        assert_eq!(response.http_status(), None);
        assert!(matches!(response.outcome(), InvoiceOutcome::Unknown));
        assert_eq!(response.ensure_accepted().err().unwrap().code(), 10);
        let results = response.validation_results().ok().unwrap();
        drop(response);
        assert_eq!(results.info_len(), 1);
        assert_eq!(results.warning_len(), 1);
        assert_eq!(results.error_len(), 0);
        assert!(results.info_message(1).is_err());
        assert!(results.warning_message(usize::MAX).is_err());
        assert!(results.error_message(0).is_err());
        let message = results.info_message(0).ok().unwrap();
        drop(results);
        assert_eq!(message.message().ok().unwrap().unwrap().0, "retained");
    }

    #[test]
    fn response_rejects_nul_text_and_invalid_cleared_xml() {
        for encoded in ["", "!!!", "AA==", "/w=="] {
            let response = ValidationResponse(
                serde_json::from_value(serde_json::json!({
                    "validationResults": {}, "clearedInvoice": encoded
                }))
                .unwrap(),
            );
            assert_eq!(response.cleared_invoice_xml().err().unwrap().code(), 3);
        }
        let response = ValidationResponse(
            serde_json::from_value(serde_json::json!({
                "validationResults": {}, "reportingStatus": "REPORTED\u{0000}"
            }))
            .unwrap(),
        );
        assert_eq!(response.reporting_status().err().unwrap().code(), 1);
        assert!(response.cleared_invoice_xml().ok().unwrap().is_none());
    }
}
