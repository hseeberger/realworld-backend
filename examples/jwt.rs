use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_URL_SAFE, Engine};
use clap::{Parser, Subcommand};
use jwt_simple::prelude::{Claims, HS256Key, MACLike, NoCustomClaims, VerificationOptions};
use std::{env, time::Duration};

fn main() -> Result<()> {
    Cli::parse().run()
}

#[derive(Debug, Parser)]
#[command()]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    GenerateKey,
    CreateToken { subject: String },
    VerifyToken { token: String },
}

impl Cli {
    fn run(self) -> Result<()> {
        match self.command {
            Command::GenerateKey => generate_key(),
            Command::CreateToken { subject } => create_token(subject)?,
            Command::VerifyToken { token } => verify_token(&token)?,
        };
        Ok(())
    }
}

fn generate_key() {
    let key = HS256Key::generate();
    let key = BASE64_URL_SAFE.encode(key.to_bytes());
    println!("{key}");
}

fn create_token<T>(subject: T) -> Result<()>
where
    T: ToString,
{
    let key = make_key()?;

    let expiry = Duration::from_secs(2 * 3600);
    let claims = Claims::create(expiry.into()).with_subject(subject);

    let token = key.authenticate(claims).context("authenticate claims")?;
    println!("{token}");

    Ok(())
}

fn verify_token(token: &str) -> Result<()> {
    let key = make_key()?;

    let verification_options = Some(VerificationOptions {
        time_tolerance: Some(Duration::from_secs(60).into()),
        ..Default::default()
    });

    let subject = key
        .verify_token::<NoCustomClaims>(token, verification_options)
        .context("verify token")
        .and_then(|claims| claims.subject.ok_or(anyhow!("JWT token has no subject")))?;
    println!("subject: {subject}");

    Ok(())
}

fn make_key() -> Result<HS256Key> {
    let key = env::var("JWT_KEY").context("get JWT_KEY env var")?;
    BASE64_URL_SAFE
        .decode(key)
        .context("decode key as Base64")
        .map(|ref key| HS256Key::from_bytes(key))
}
