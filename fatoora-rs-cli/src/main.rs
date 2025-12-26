use anyhow::Result;
use clap::{Parser, Subcommand};

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
    },
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
            todo!("Implement CSR generation");
        }
        Commands::Sign {
            invoice,
            signed_invoice,
        } => {
            let signed = fatoora_core::sign::sign_invoice(&invoice)?;
            println!("{}", signed);
        }
        Commands::Validate { invoice } => {
            todo!()
        }
        Commands::Qr { invoice } => {
            todo!()
        }
        Commands::GenerateHash { invoice } => {
            let hash = fatoora_core::sign::generate_hash(&invoice)?;
            println!("{}", hash);
        }
        Commands::InvoiceRequest {
            invoice,
            api_request,
        } => {
            todo!()
        }
    }

    Ok(())
}
