use std::{fs, io::Read, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use vpn_anon_core::{config::AwgProfile, migration::ImportManifest};
use zeroize::Zeroizing;

const MAX_PROFILE: u64 = 256 * 1024;

#[derive(Parser)]
#[command(
    name = "vpn-anon",
    version,
    about = "Safe AWG profile validation and user migration planning"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Inspect {
        config: PathBuf,
    },
    InspectStdin,
    PlanMigration {
        manifest: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect { config } => {
            let file = fs::File::open(&config)
                .with_context(|| format!("cannot open {}", config.display()))?;
            let metadata = file
                .metadata()
                .with_context(|| format!("cannot inspect {}", config.display()))?;
            anyhow::ensure!(
                metadata.is_file() && metadata.len() > 0 && metadata.len() <= MAX_PROFILE,
                "profile is empty or exceeds 256 KiB"
            );
            let mut source = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
            file.take(MAX_PROFILE + 1)
                .read_to_end(&mut source)
                .with_context(|| format!("cannot read {}", config.display()))?;
            anyhow::ensure!(
                source.len() as u64 == metadata.len(),
                "profile changed while it was being read"
            );
            let text = std::str::from_utf8(&source).context("profile is not valid UTF-8")?;
            let profile = AwgProfile::parse(text)?;
            println!("{}", serde_json::to_string_pretty(&profile.summary())?);
        }
        Command::InspectStdin => {
            let mut source = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(MAX_PROFILE + 1)
                .read_to_end(&mut source)
                .context("cannot read profile from stdin")?;
            anyhow::ensure!(
                !source.is_empty() && source.len() as u64 <= MAX_PROFILE,
                "profile is empty or exceeds 256 KiB"
            );
            let text = std::str::from_utf8(&source).context("profile is not valid UTF-8")?;
            let profile = AwgProfile::parse(text)?;
            println!("{}", serde_json::to_string_pretty(&profile.summary())?);
        }
        Command::PlanMigration { manifest, output } => {
            let input = ImportManifest::read_from(&manifest)?;
            let base = manifest
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let plan = serde_json::to_string_pretty(&input.plan(base)?)?;
            if let Some(path) = output {
                fs::write(&path, plan)
                    .with_context(|| format!("cannot write {}", path.display()))?;
            } else {
                println!("{plan}");
            }
        }
    }
    Ok(())
}
