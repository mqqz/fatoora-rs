use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing error: {0}")]
    SigningError(String),
}

pub fn generate_hash(_xml: &str) -> Result<String, SigningError> {
    // TODO: canonicalization
    // TODO: SHA-256 over invoice contents
    todo!()
}

pub fn sign_invoice(_path: &str) -> Result<String, SigningError> {
    // TODO: load private key + cert
    // TODO: canonicalize invoice
    // TODO: sign using ECDSA P-256K1
    todo!()
}
