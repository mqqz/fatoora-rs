use super::{ValidationResponse, ZatcaError};
use base64ct::{Base64, Encoding};
use std::fmt;

/// Outcome of the invoked operation. Compliance acceptance only means the check passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InvoiceOutcome {
    Accepted,
    Rejected,
    /// Missing, unrecognized, contradictory, or detached response context.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum InvoiceOperation {
    Reporting,
    Clearance,
    Compliance,
}

/// An HTTP response retained on failure, including unrecognized gateway fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseError {
    http_status: u16,
    body: String,
    validation_response: Option<ValidationResponse>,
}

impl HttpResponseError {
    pub fn http_status(&self) -> u16 {
        self.http_status
    }
    /// Response text, including fields not represented by the typed validation response.
    pub fn body(&self) -> &str {
        &self.body
    }
    pub fn validation_response(&self) -> Option<&ValidationResponse> {
        self.validation_response.as_ref()
    }
}

impl fmt::Display for HttpResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.http_status.fmt(f)
    }
}

impl ValidationResponse {
    /// Actual HTTP status, or `None` for a standalone deserialized JSON body.
    pub fn http_status(&self) -> Option<u16> {
        self.http_status
    }

    /// Classify only the invoked endpoint; unfamiliar or contradictory evidence is unknown.
    /// Warnings alone do not prevent acceptance. A compliance pass is not production acceptance.
    pub fn outcome(&self) -> InvoiceOutcome {
        let (value, accepted, rejected) = match self.operation {
            Some(InvoiceOperation::Reporting) => {
                (self.reporting_status(), "REPORTED", "NOT_REPORTED")
            }
            Some(InvoiceOperation::Clearance) => {
                (self.clearance_status(), "CLEARED", "NOT_CLEARED")
            }
            Some(InvoiceOperation::Compliance) => {
                (self.validation_results().status(), "PASS", "ERROR")
            }
            None => return InvoiceOutcome::Unknown,
        };
        if value == Some(rejected) {
            return InvoiceOutcome::Rejected;
        }
        let accepted = value == Some(accepted)
            || (self.operation == Some(InvoiceOperation::Compliance) && value == Some("WARNING"));
        if accepted {
            if self.validation_results().status() == Some("ERROR")
                || !self.validation_results().error_messages().is_empty()
            {
                return InvoiceOutcome::Unknown;
            }
            return InvoiceOutcome::Accepted;
        }
        InvoiceOutcome::Unknown
    }

    /// Fail for rejected or unknown outcomes, retaining the response for inspection.
    pub fn ensure_accepted(&self) -> Result<(), ZatcaError> {
        if self.outcome() == InvoiceOutcome::Accepted {
            Ok(())
        } else {
            Err(ZatcaError::NotAccepted(Box::new(self.clone())))
        }
    }

    /// Exact base64 field returned by the gateway; presence does not establish authenticity.
    pub fn cleared_invoice_base64(&self) -> Option<&str> {
        self.cleared_invoice.as_deref()
    }

    /// Decode the returned invoice without XML parsing, normalization, or signature verification.
    /// Missing content returns `None`; empty, invalid base64, NUL, or invalid UTF-8 content is an error.
    pub fn cleared_invoice_xml(&self) -> Result<Option<String>, ZatcaError> {
        let Some(encoded) = self.cleared_invoice_base64() else {
            return Ok(None);
        };
        let fail = |message: String| ZatcaError::ClearedInvoice {
            http_status: self.http_status(),
            message,
        };
        let bytes = Base64::decode_vec(encoded).map_err(|e| fail(e.to_string()))?;
        if bytes.is_empty() {
            return Err(fail("empty cleared invoice".into()));
        }
        if bytes.contains(&0) {
            return Err(fail(
                "cleared invoice contains NUL, which is not valid XML text".into(),
            ));
        }
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|e| fail(e.to_string()))
    }
}

pub(super) async fn read_validation_response(
    response: reqwest::Response,
    operation: InvoiceOperation,
) -> Result<ValidationResponse, ZatcaError> {
    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .map_err(|e| ZatcaError::ResponseRead {
            http_status: status,
            message: e.to_string(),
        })?;
    let parsed = serde_json::from_str::<ValidationResponse>(&body).map(|mut parsed| {
        parsed.http_status = Some(status);
        parsed.operation = Some(operation);
        parsed
    });
    if !(200..300).contains(&status) {
        return Err(ZatcaError::Response(Box::new(HttpResponseError {
            http_status: status,
            body,
            validation_response: parsed.ok(),
        })));
    }
    parsed.map_err(|e| ZatcaError::ResponseDecode {
        response: Box::new(HttpResponseError {
            http_status: status,
            body,
            validation_response: None,
        }),
        message: e.to_string(),
    })
}
