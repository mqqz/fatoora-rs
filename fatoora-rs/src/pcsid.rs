use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PcsidResponse {
    pub request_id: String,
    pub binary_security_token: String,
}
