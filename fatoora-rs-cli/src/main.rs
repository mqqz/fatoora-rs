use clap::{Parser, Subcommand};
use anyhow::Result;

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
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Csr { csr_config, private_key, generated_csr, pem } => {
            let csr = fatoora_rs::csr::generate_csr_from_file(&csr_config)?;
            println!("{}", csr);
        }
        Commands::Sign { invoice, signed_invoice } => {
            let signed = fatoora_rs::sign::sign_invoice(&invoice)?;
            println!("{}", signed);
        }
        Commands::Validate { invoice } => {
            let result = fatoora_rs::validate::validate_xml(&invoice)?;
            println!("{:#?}", result);
        }
        Commands::Qr { invoice } => {
            let qr = fatoora_rs::qr::generate_invoice_qr(&invoice)?;
            println!("{}", qr);
        }
        Commands::GenerateHash { invoice } => {
            let hash = fatoora_rs::sign::generate_hash(&invoice)?;
            println!("{}", hash);
        }
        Commands::InvoiceRequest { invoice, api_request } => {
            let json = fatoora_rs::api_request::generate(&invoice)?;
            println!("{}", json);
        }
    }

    Ok(())
}
