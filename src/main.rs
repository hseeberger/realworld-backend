#![feature(assert_matches)]
#![feature(async_fn_in_trait)]
#![feature(lazy_cell)]
#![feature(return_position_impl_trait_in_trait)]

mod api;
mod domain;
mod infra;

use crate::infra::{sqlite_repository::SqliteRepository, token_factory::TokenFactory};
use anyhow::{Context, Result};
use configured::Configured;
use infra::{sqlite_repository, token_factory};
use serde::Deserialize;
use tracing::{error, info};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    if let Err(error) = init_tracing() {
        eprintln!("realworld-backend exited with ERROR: {error}");
    }

    if let Err(ref error) = run().await {
        error!(
            error = format!("{error:#}"),
            backtrace = %error.backtrace(),
            "realworld-backend exited with ERROR"
        );
    };
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Config {
    api: api::Config,
    sqlite: sqlite_repository::Config,
    token_factory: token_factory::Config,
}

fn init_tracing() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().json())
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

    api::serve(config.api, repository, token_factory).await
}
