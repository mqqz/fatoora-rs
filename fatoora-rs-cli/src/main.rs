//! Command-line interface for the `fatoora-core` ZATCA SDK.
//!
//! # Examples
//! ```bash
//! fatoora-rs-cli csr --csr-config csr.properties --generated-csr csr.pem --private-key key.pem
//! ```
use anyhow::{Context, Result, bail};
use base64ct::{Base64, Encoding};
use clap::{Parser, Subcommand, ValueEnum};
use fatoora_core::{
    config::EnvironmentType,
    csr::{CsrProperties, ToBase64String},
    invoice::{
        sign::invoice_hash_base64, validation::validate_xml_invoice_from_file,
        xml::parse::parse_signed_invoice_xml,
    },
};
use k256::pkcs8::{EncodePrivateKey, LineEnding};
use libxml::parser::Parser as XmlParser;
use serde_json::json;
use std::path::Path;
use x509_cert::der::EncodePem;

#[derive(Parser)]
#[command(name = "fatoora")]
#[command(about = "Rust-based ZATCA E-Invoice CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Csr {
        #[arg(long, help = "Path to CSR properties file")]
        csr_config: String,
        #[arg(long, help = "Write generated private key to this path")]
        private_key: Option<String>,
        #[arg(long, help = "Write generated CSR to this path")]
        generated_csr: Option<String>,
        #[arg(long, help = "Output PEM instead of base64 DER")]
        pem: bool,
    },
    Sign {
        #[arg(long, help = "Path to input invoice XML")]
        invoice: String,
        #[arg(long, help = "Path to signing certificate")]
        cert: String,
        #[arg(long, help = "Path to signing key")]
        key: String,
        #[arg(long, value_enum, default_value_t = KeyFormat::Pem, help = "Certificate format")]
        cert_format: KeyFormat,
        #[arg(long, value_enum, default_value_t = KeyFormat::Pem, help = "Key format")]
        key_format: KeyFormat,
        #[arg(long, help = "Write signed invoice XML to this path")]
        signed_invoice: Option<String>,
    },
    Validate {
        #[arg(long, help = "Path to invoice XML")]
        invoice: String,
        #[arg(long, help = "Path to UBL XSD schema root invoice file")]
        xsd_path: Option<String>,
    },
    Qr {
        #[arg(long, help = "Path to signed invoice XML")]
        invoice: String,
    },
    GenerateHash {
        #[arg(long, help = "Path to invoice XML")]
        invoice: String,
    },
    InvoiceRequest {
        #[arg(long, help = "Path to signed invoice XML")]
        invoice: String,
        #[arg(long, help = "Write JSON request payload to this path")]
        api_request: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum KeyFormat {
    Pem,
    Der,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Csr {
            csr_config,
            private_key,
            generated_csr,
            pem,
        } => {
            let csr_config = CsrProperties::parse_csr_config(Path::new(&csr_config))
                .context("failed to parse CSR config")?;
            let (csr, signer) = csr_config
                .build_with_rng(EnvironmentType::NonProduction)
                .context("failed to generate CSR")?;

            let csr_output = if pem {
                csr.to_pem(LineEnding::LF)
                    .context("failed to encode CSR as PEM")?
            } else {
                csr.to_base64_string()
                    .context("failed to encode CSR as base64")?
            };

            let key_output = if pem {
                signer
                    .to_pkcs8_pem(LineEnding::LF)
                    .context("failed to encode private key as PEM")?
                    .to_string()
            } else {
                let der = signer
                    .to_pkcs8_der()
                    .context("failed to encode private key as DER")?;
                Base64::encode_string(der.as_bytes())
            };

            if let Some(path) = generated_csr {
                std::fs::write(&path, csr_output.as_bytes())
                    .with_context(|| format!("failed to write CSR to {path}"))?;
            } else {
                println!("{csr_output}");
            }

            if let Some(path) = private_key {
                std::fs::write(&path, key_output.as_bytes())
                    .with_context(|| format!("failed to write private key to {path}"))?;
            } else {
                println!("{key_output}");
            }
        }
        Commands::Sign {
            invoice,
            cert,
            key,
            cert_format,
            key_format,
            signed_invoice,
        } => {
            let xml = std::fs::read_to_string(&invoice)
                .with_context(|| format!("failed to read invoice file {invoice}"))?;

            let signer = match (cert_format, key_format) {
                (KeyFormat::Pem, KeyFormat::Pem) => {
                    let cert_pem = std::fs::read_to_string(&cert)
                        .with_context(|| format!("failed to read cert file {cert}"))?;
                    let key_pem = std::fs::read_to_string(&key)
                        .with_context(|| format!("failed to read key file {key}"))?;
                    fatoora_core::invoice::sign::InvoiceSigner::from_pem(
                        cert_pem.trim(),
                        key_pem.trim(),
                    )?
                }
                (KeyFormat::Der, KeyFormat::Der) => {
                    let cert_der = std::fs::read(&cert)
                        .with_context(|| format!("failed to read cert file {cert}"))?;
                    let key_der = std::fs::read(&key)
                        .with_context(|| format!("failed to read key file {key}"))?;
                    fatoora_core::invoice::sign::InvoiceSigner::from_der(&cert_der, &key_der)?
                }
                _ => {
                    bail!("mixed PEM/DER formats are not supported; use matching formats");
                }
            };

            let signed_xml = signer.sign_xml(&xml)?;
            if let Some(path) = signed_invoice {
                std::fs::write(&path, signed_xml.as_bytes())
                    .with_context(|| format!("failed to write signed invoice to {path}"))?;
            } else {
                println!("{signed_xml}");
            }
        }
        Commands::Validate { invoice, xsd_path } => {
            let config = match xsd_path {
                Some(path) => {
                    let path_ref = Path::new(&path);
                    if !path_ref.exists() {
                        bail!(
                            "XSD path not found: {path}. Provide a valid path via --xsd-path."
                        );
                    }
                    fatoora_core::config::Config::with_xsd_path(
                        EnvironmentType::NonProduction,
                        path_ref,
                    )
                }
                None => {
                    let default_path = resolve_xsd_path();
                    if !default_path.exists() {
                        bail!(
                            "XSD not found at default location: {}. Provide --xsd-path.",
                            default_path.display()
                        );
                    }
                    fatoora_core::config::Config::with_xsd_path(
                        EnvironmentType::NonProduction,
                        default_path,
                    )
                }
            };
            validate_xml_invoice_from_file(Path::new(&invoice), &config)
                .map_err(|error| anyhow::anyhow!("XML validation failed: {error}"))?;
            println!("OK");
        }
        Commands::Qr { invoice } => {
            let xml = std::fs::read_to_string(&invoice)
                .with_context(|| format!("failed to read invoice file {invoice}"))?;
            let signed = parse_signed_invoice_xml(&xml)
                .with_context(|| format!("failed to parse signed invoice from {invoice}"))?;
            println!("{}", signed.qr_code());
        }
        Commands::GenerateHash { invoice } => {
            let xml = std::fs::read_to_string(&invoice)
                .with_context(|| format!("failed to read invoice file {invoice}"))?;
            let doc = XmlParser::default()
                .parse_string(&xml)
                .with_context(|| format!("failed to parse XML from {invoice}"))?;
            let hash = invoice_hash_base64(&doc)?;
            println!("{hash}");
        }
        Commands::InvoiceRequest {
            invoice,
            api_request,
        } => {
            let xml = std::fs::read_to_string(&invoice)
                .with_context(|| format!("failed to read invoice file {invoice}"))?;
            let signed = parse_signed_invoice_xml(&xml)
                .with_context(|| format!("failed to parse signed invoice from {invoice}"))?;
            let payload = json!({
                "invoiceHash": signed.invoice_hash(),
                "uuid": signed.uuid(),
                "invoice": signed.to_xml_base64(),
            });
            let output = serde_json::to_string_pretty(&payload)
                .context("failed to serialize invoice request")?;

            if let Some(path) = api_request {
                std::fs::write(&path, output.as_bytes())
                    .with_context(|| format!("failed to write request to {path}"))?;
            } else {
                println!("{output}");
            }
        }
    }

    Ok(())
}

fn resolve_xsd_path() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::new());
    if let Some(dir) = path.parent() {
        path = dir.to_path_buf();
    }
    path.join("assets")
        .join("schemas")
        .join("UBL2.1")
        .join("xsd")
        .join("maindoc")
        .join("UBL-Invoice-2.1.xsd")
}
