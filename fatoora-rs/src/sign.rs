use anyhow::Result;

pub fn generate_hash(xml: &str) -> Result<String> {
    // TODO: canonicalization
    // TODO: SHA-256 over invoice contents
    Ok("HASH_PLACEHOLDER".into())
}

pub fn sign_invoice(path: &str) -> Result<String> {
    // TODO: load private key + cert
    // TODO: canonicalize invoice
    // TODO: sign using ECDSA P-256K1
    Ok("<SignedInvoice/>".into())
}
