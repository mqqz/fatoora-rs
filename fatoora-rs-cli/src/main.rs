use anyhow::{Context, Result, bail};
use base64ct::{Base64, Encoding};
use clap::{Parser, Subcommand, ValueEnum};
use fatoora_core::{
    config::EnvironmentType,
    csr::{CsrProperties, ToBase64String},
    invoice::validation::validate_xml_invoice_from_file,
};
use k256::pkcs8::{EncodePrivateKey, LineEnding};
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
        #[arg(long)]
        csr_config: String,
        #[arg(long)]
        private_key: Option<String>,
        #[arg(long)]
        generated_csr: Option<String>,
        #[arg(long)]
        pem: bool,
    },
    Sign {
        #[arg(long)]
        invoice: String,
        #[arg(long)]
        cert: String,
        #[arg(long)]
        key: String,
        #[arg(long, value_enum, default_value_t = KeyFormat::Pem)]
        cert_format: KeyFormat,
        #[arg(long, value_enum, default_value_t = KeyFormat::Pem)]
        key_format: KeyFormat,
        #[arg(long)]
        signed_invoice: Option<String>,
    },
    Validate {
        #[arg(long)]
        invoice: String,
    },
    Qr {
        #[arg(long)]
        invoice: String,
    },
    GenerateHash {
        #[arg(long)]
        invoice: String,
    },
    InvoiceRequest {
        #[arg(long)]
        invoice: String,
        #[arg(long)]
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
        Commands::Validate { invoice } => {
            let config = Default::default();
            validate_xml_invoice_from_file(Path::new(&invoice), &config)
                .map_err(|error| anyhow::anyhow!("XML validation failed: {error}"))?;
            println!("OK");
        }
        Commands::Qr { invoice: _ } => {
            bail!("QR extraction is not wired yet: no XML->invoice parser or QR extractor");
        }
        Commands::GenerateHash { invoice: _invoice } => {
            todo!()
        }
        Commands::InvoiceRequest {
            invoice: _,
            api_request: _,
        } => {
            bail!("invoice request generation is not wired yet");
        }
    }

    Ok(())
}
