use std::io::{stdin, stdout, Write};

use anyhow::Context;
use clap::{Parser, Subcommand};
use signum::{ensure_gpg, SignumManager};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "signum",
    about = "Manage token-based multi-factor authentication",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Configure the GPG identity used to encrypt and decrypt secrets
    Configure,
    /// List all configured profiles
    List,
    /// Add a new profile (prompts for the TOTP secret)
    Add { name: String },
    /// Remove a profile
    Remove {
        name: String,
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Generate a token for a profile
    Token { name: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut manager = SignumManager::new().context("failed to initialize signum")?;

    match cli.command {
        Command::Configure => configure(&mut manager)?,
        Command::List => list(&manager)?,
        Command::Add { name } => {
            ensure_gpg()?;
            add(&mut manager, &name)?;
        }
        Command::Remove { name, yes } => remove(&manager, &name, yes)?,
        Command::Token { name } => {
            ensure_gpg()?;
            token(&manager, &name)?;
        }
    }

    Ok(())
}

fn configure(manager: &mut SignumManager) -> anyhow::Result<()> {
    println!("Configuring...");

    let user_id = read_input("Please input user ID/e-mail: ")?;
    let key_id = read_input("Please input GPG key ID: ")?;

    manager.configure(&user_id, &key_id)?;
    println!("Configured!");
    Ok(())
}

fn list(manager: &SignumManager) -> anyhow::Result<()> {
    println!("Listing...");

    let profiles = manager.list_profiles()?;
    for profile in profiles {
        println!("{profile}");
    }
    Ok(())
}

fn add(manager: &mut SignumManager, name: &str) -> anyhow::Result<()> {
    println!("Adding, name: {name}");

    let secret = Zeroizing::new(rpassword::prompt_password("Secret (TOTP seed, base32): ")?);
    let secret = secret.trim();
    if secret.is_empty() {
        anyhow::bail!("secret cannot be empty");
    }

    manager.add_profile(name, secret)?;
    println!("Added, name: {name}");

    // Generate initial token
    token(manager, name)
}

fn remove(manager: &SignumManager, name: &str, skip_confirmation: bool) -> anyhow::Result<()> {
    if !skip_confirmation {
        let answer = read_input(&format!(
            "Remove profile '{name}'? This cannot be undone. [y/N]: "
        ))?;
        if !matches!(answer.as_str(), "y" | "Y" | "yes" | "Yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!("Removing, name: {name}");

    manager.remove_profile(name)?;
    println!("Removed, name: {name}");
    Ok(())
}

fn token(manager: &SignumManager, name: &str) -> anyhow::Result<()> {
    println!("Token for: {name}");

    let token = manager.generate_token(name)?;
    println!("{token}");
    Ok(())
}

fn read_input(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    stdout().flush()?;

    let mut input = String::new();
    stdin().read_line(&mut input)?;

    Ok(input.trim().to_string())
}
