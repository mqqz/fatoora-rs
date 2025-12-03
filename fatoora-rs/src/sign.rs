use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing error: {0}")]
    SigningError(String),
}

pub fn generate_hash(xml: &str) -> Result<String, SigningError> {
    // TODO: canonicalization
    // TODO: SHA-256 over invoice contents
    Ok("HASH_PLACEHOLDER".into())
}

pub fn sign_invoice(path: &str) -> Result<String, SigningError> {
    // TODO: load private key + cert
    // TODO: canonicalize invoice
    // TODO: sign using ECDSA P-256K1
    Ok("<SignedInvoice/>".into())
}
