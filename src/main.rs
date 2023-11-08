#![feature(assert_matches)]
#![feature(lazy_cell)]

mod api;
mod domain;
mod infra;

use crate::{
    domain::user::UserService,
    infra::{sqlite_repository::SqliteRepository, token_factory::TokenFactory},
};
use anyhow::{Context, Result};
use configured::Configured;
use infra::{sqlite_repository, token_factory};
use serde::Deserialize;
use serde_json::json;
use std::panic;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tracing::{error, info};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    // If tracing initialization fails, nevertheless emit a structured log event.
    if let Err(error) = init_tracing() {
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        let error = serde_json::to_string(&json!({
            "timestamp": now,
            "level": "ERROR",
            "message": "process exited with ERROR",
            "error": format!("{error:#}")
        }));
        // Not using `eprintln!`, because `tracing_subscriber::fmt` uses stdout by default.
        println!("{}", error.unwrap());
        return;
    }

    // Replace the default panic hook with one that uses structured logging at ERROR level.
    panic::set_hook(Box::new(|panic| error!(%panic, "process panicked")));

    // Run and log any error.
    if let Err(error) = run().await {
        error!(
            error = format!("{error:#}"),
            backtrace = %error.backtrace(),
            "process exited with ERROR"
        );
    };
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Config {
    api: api::Config,
    sqlite: sqlite_repository::Config,
    token_factory: token_factory::Config,
}

fn init_tracing() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().json().flatten_event(true))
        .try_init()
        .context("initialize tracing subscriber")
}

async fn run() -> Result<()> {
    let config = Config::load().context("load configuration")?;

    info!(?config, "starting");

    let repository = SqliteRepository::new(config.sqlite)
        .await
        .context("create SqliteRepository")?;

    let token_factory = TokenFactory::new(config.token_factory).context("create TokenFactory")?;

    let user_service = UserService::new(repository);

    api::serve(config.api, user_service, token_factory).await
}
