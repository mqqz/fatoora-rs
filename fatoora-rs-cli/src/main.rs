//! Command-line interface for the `fatoora-core` ZATCA SDK.
//!
//! # Examples
//! ```bash
//! fatoora-rs-cli csr --csr-config csr.properties --generated-csr csr.pem --private-key key.pem
//! ```
use anyhow::{bail, Context, Result};
use base64ct::{Base64, Encoding};
use clap::{Parser, Subcommand, ValueEnum};
use fatoora_core::{
    config::EnvironmentType,
    csr::CsrProperties,
    invoice::{
        validation::validate_xml_invoice_from_str,
        xml::parse::{parse_finalized_invoice_xml, parse_signed_invoice_xml},
        FinalizedInvoice, SignedInvoice,
    },
};
use serde_json::json;

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
    },
    Qr {
        #[arg(long, help = "Path to invoice XML (finalized or signed)")]
        invoice: String,
        #[arg(
            long,
            help = "Fail if invoice is already signed (contains existing QR/signature fields)"
        )]
        fail_on_signed: bool,
    },
    QrRead {
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
            let csr_contents = std::fs::read_to_string(&csr_config)
                .with_context(|| format!("failed to read CSR config from {csr_config}"))?;
            let csr_config = CsrProperties::from_properties_str(&csr_contents)
                .context("failed to parse CSR config")?;
            let signer = fatoora_core::csr::SigningKey::generate();
            let csr = csr_config
                .build(&signer, EnvironmentType::NonProduction)
                .context("failed to generate CSR")?;

            let csr_output = if pem {
                csr.to_pem().context("failed to encode CSR as PEM")?
            } else {
                csr.to_base64().context("failed to encode CSR as base64")?
            };

            let key_output = if pem {
                signer
                    .to_pem()
                    .context("failed to encode private key as PEM")?
            } else {
                let der = signer
                    .to_der()
                    .context("failed to encode private key as DER")?;
                Base64::encode_string(&der)
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
            let config = fatoora_core::config::Config::new(EnvironmentType::NonProduction);
            let xml = std::fs::read_to_string(&invoice)
                .with_context(|| format!("failed to read invoice file {invoice}"))?;
            validate_xml_invoice_from_str(&xml, &config)
                .map_err(|error| anyhow::anyhow!("XML validation failed: {error}"))?;
            println!("OK");
        }
        Commands::Qr {
            invoice,
            fail_on_signed,
        } => {
            let xml = std::fs::read_to_string(&invoice)
                .with_context(|| format!("failed to read invoice file {invoice}"))?;
            let qr = match parse_signed_invoice_xml(&xml) {
                Ok(signed) => {
                    if fail_on_signed {
                        bail!(
                            "invoice {invoice} is signed; refuse to regenerate QR when --fail-on-signed is set"
                        );
                    }
                    generate_signed_invoice_qr(&signed)?
                }
                Err(signed_parse_error) => {
                    let finalized = parse_finalized_invoice_xml(&xml).with_context(|| {
                        format!(
                            "failed to parse invoice XML from {invoice}; signed parse error: {signed_parse_error}"
                        )
                    })?;
                    generate_finalized_invoice_qr(&finalized)?
                }
            };
            println!("{qr}");
        }
        Commands::QrRead { invoice } => {
            let xml = std::fs::read_to_string(&invoice)
                .with_context(|| format!("failed to read invoice file {invoice}"))?;
            let signed = parse_signed_invoice_xml(&xml)
                .with_context(|| format!("failed to parse signed invoice from {invoice}"))?;
            println!("{}", signed.qr_code());
        }
        Commands::GenerateHash { invoice } => {
            let xml = std::fs::read_to_string(&invoice)
                .with_context(|| format!("failed to read invoice file {invoice}"))?;
            let hash = match parse_signed_invoice_xml(&xml) {
                Ok(signed) => signed.hash_base64()?,
                Err(_) => parse_finalized_invoice_xml(&xml)
                    .with_context(|| format!("failed to parse invoice XML from {invoice}"))?
                    .hash_base64()?,
            };
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

fn generate_finalized_invoice_qr(invoice: &FinalizedInvoice) -> Result<String> {
    build_qr_payload(invoice.data(), invoice.totals(), None)
}

fn generate_signed_invoice_qr(invoice: &SignedInvoice) -> Result<String> {
    build_qr_payload(
        invoice.data(),
        invoice.totals(),
        Some((
            invoice.invoice_hash(),
            invoice.signature(),
            invoice.public_key(),
            invoice.zatca_key_signature(),
        )),
    )
}

fn build_qr_payload(
    data: &fatoora_core::invoice::InvoiceData,
    totals: &fatoora_core::invoice::InvoiceTotalsData,
    signing_parts: Option<(&str, &str, &str, Option<&str>)>,
) -> Result<String> {
    let seller_name = data.seller().name().trim();
    if seller_name.is_empty() {
        bail!("seller legal name is missing");
    }
    let seller_vat = data
        .seller()
        .vat_id()
        .map(|vat| vat.as_str().trim())
        .filter(|vat| !vat.is_empty())
        .ok_or_else(|| anyhow::anyhow!("seller VAT ID is missing"))?;

    let timestamp = data
        .issue_datetime()
        .as_str()
        .trim_end_matches('Z')
        .to_string();
    let total_with_vat = format!("{:.2}", totals.tax_inclusive_amount());
    let total_vat = format!("{:.2}", totals.tax_amount());

    let mut tlv = Vec::new();
    push_tlv_field(&mut tlv, 1, seller_name.as_bytes())?;
    push_tlv_field(&mut tlv, 2, seller_vat.as_bytes())?;
    push_tlv_field(&mut tlv, 3, timestamp.as_bytes())?;
    push_tlv_field(&mut tlv, 4, total_with_vat.as_bytes())?;
    push_tlv_field(&mut tlv, 5, total_vat.as_bytes())?;

    if let Some((invoice_hash, signature, public_key_b64, zatca_key_signature_b64)) = signing_parts
    {
        push_tlv_field(&mut tlv, 6, invoice_hash.as_bytes())?;
        push_tlv_field(&mut tlv, 7, signature.as_bytes())?;
        let public_key_bytes = Base64::decode_vec(public_key_b64)
            .context("failed to decode signed invoice public key (base64)")?;
        push_tlv_field(&mut tlv, 8, &public_key_bytes)?;
        if let Some(stamp_b64) = zatca_key_signature_b64 {
            let stamp_bytes = Base64::decode_vec(stamp_b64)
                .context("failed to decode ZATCA key signature (base64)")?;
            push_tlv_field(&mut tlv, 9, &stamp_bytes)?;
        }
    }

    let encoded = Base64::encode_string(&tlv);
    if encoded.len() > 700 {
        bail!(
            "QR code payload exceeds 700 characters once base64 encoded (len={})",
            encoded.len()
        );
    }
    Ok(encoded)
}

fn push_tlv_field(buffer: &mut Vec<u8>, tag: u8, value: &[u8]) -> Result<()> {
    if value.len() > u8::MAX as usize {
        bail!("TLV field {tag} exceeds 255 bytes (len={})", value.len());
    }
    buffer.push(tag);
    buffer.push(value.len() as u8);
    buffer.extend_from_slice(value);
    Ok(())
}
