use base64ct::{Base64, Encoding};
use libxml::{
    parser::Parser,
    tree::{Document, c14n},
    xpath,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing error: {0}")]
    SigningError(String),
}

pub fn generate_hash(xml: &Document) -> Result<String, SigningError> {
    // Duplicate the document to avoid modifying the original
    let xml = xml
        .dup()
        .map_err(|e| SigningError::SigningError(format!("Failed to duplicate xml: {:#?}", e)))?;
    // 1: Remove tags (UBLExtension, QR code, Signature)
    let ctx = xpath::Context::new(&xml)
        .map_err(|e| SigningError::SigningError(format!("XPath context error: {:#?}", e)))?;

    ctx.register_namespace(
        "cbc",
        "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    )
    .map_err(|e| SigningError::SigningError(format!("XPath context error: {:#?}", e)))?;

    let xpaths = [
        "*[local-name()='Invoice']//*[local-name()='UBLExtensions']",
        "//*[local-name()='AdditionalDocumentReference'][cbc:ID[normalize-space(text())='QR']]",
        "*[local-name()='Invoice']//*[local-name()='Signature']",
    ];

    for xp in xpaths {
        let nodes = ctx
            .evaluate(xp)
            .map_err(|e| SigningError::SigningError(format!("XPath context error: {:#?}", e)))?
            .get_nodes_as_vec();

        for mut node in nodes {
            node.unlink(); // removes from parent
        }
    }
    // 2: Remove XML version (I believe libxml does not include it in canonicalization)
    // 3: Canonicalize
    let canon_opts = c14n::CanonicalizationOptions {
        mode: c14n::CanonicalizationMode::Canonical1_1,
        inclusive_ns_prefixes: vec![],
        with_comments: false,
    };
    let canonicalized = xml
        .canonicalize(canon_opts, None)
        .map_err(|e| SigningError::SigningError(format!("Failed to canonicalize xml: {:#?}", e)))?;

    // 4:Hash the body SHA256
    let hash = Sha256::digest(&canonicalized)
        .as_slice()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // 5: Base64 Encode
    Ok(Base64::encode_string(hash.as_bytes()))
}

pub fn sign_invoice(_path: &str) -> Result<String, SigningError> {
    // TODO: load private key + cert
    // TODO: canonicalize invoice
    // TODO: sign using ECDSA P-256K1
    todo!()
}

pub fn generate_hash_from_str(xml: &str) -> Result<String, SigningError> {
    let doc = Parser::default()
        .parse_string(xml)
        .map_err(|e| SigningError::SigningError(format!("XML parse error: {e:?}")))?;
    generate_hash(&doc)
}
